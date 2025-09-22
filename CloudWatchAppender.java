import java.io.Serializable;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.core.layout.PatternLayout;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.CreateLogGroupRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.CreateLogStreamRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.InputLogEvent;
import software.amazon.awssdk.services.cloudwatchlogs.model.InvalidSequenceTokenException;
import software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsResponse;
import software.amazon.awssdk.services.cloudwatchlogs.model.ResourceAlreadyExistsException;

@Plugin(name = "CloudWatchAppender", category = "Core", elementType = "appender", printObject = true)
public class CloudWatchAppender extends AbstractAppender {

    private final String logGroupName;
    private final String logStreamName;
    private final CloudWatchLogsClient client;
    private final BlockingQueue<InputLogEvent> queue = new LinkedBlockingQueue<>(10000); // Max queue size
    private final Layout<? extends Serializable> layout;
    private volatile String nextSequenceToken = null;
    private ScheduledExecutorService executor;

    private static final Pattern SEQUENCE_TOKEN_PATTERN = Pattern.compile("The given sequenceToken is invalid. The next expected sequenceToken is: '(\\d+)'");

    protected CloudWatchAppender(String name, Filter filter, Layout<? extends Serializable> layout,
                                 boolean ignoreExceptions, Property[] properties, String logGroupName,
                                 String logStreamName, CloudWatchLogsClient client) {
        super(name, filter, layout, ignoreExceptions, properties);
        this.logGroupName = logGroupName;
        this.logStreamName = logStreamName;
        this.client = client;
        this.layout = layout;
    }

    @PluginFactory
    public static CloudWatchAppender createAppender(
            @PluginAttribute("name") String name,
            @PluginAttribute("logGroupName") String logGroupName,
            @PluginAttribute("logStreamName") String logStreamName,
            @PluginAttribute("region") String regionStr,
            @PluginAttribute("accessKeyId") String accessKeyId,
            @PluginAttribute("secretAccessKey") String secretAccessKey,
            @PluginElement("Layout") Layout<? extends Serializable> layout,
            @PluginElement("Filter") Filter filter,
            @PluginAttribute(value = "ignoreExceptions", defaultBoolean = true) boolean ignoreExceptions) {

        if (name == null) {
            LOGGER.error("No name provided for CloudWatchAppender");
            return null;
        }
        if (logGroupName == null) {
            LOGGER.error("No logGroupName provided for CloudWatchAppender");
            return null;
        }
        if (logStreamName == null) {
            LOGGER.error("No logStreamName provided for CloudWatchAppender");
            return null;
        }
        if (regionStr == null) {
            LOGGER.error("No region provided for CloudWatchAppender");
            return null;
        }
        if (layout == null) {
            layout = PatternLayout.createDefaultLayout();
        }

        Region region = Region.of(regionStr);
        AwsCredentialsProvider credentialsProvider;
        if (accessKeyId != null && !accessKeyId.isEmpty() && secretAccessKey != null && !secretAccessKey.isEmpty()) {
            AwsBasicCredentials credentials = AwsBasicCredentials.create(accessKeyId, secretAccessKey);
            credentialsProvider = StaticCredentialsProvider.create(credentials);
        } else {
            credentialsProvider = DefaultCredentialsProvider.create();
        }

        CloudWatchLogsClient client = CloudWatchLogsClient.builder()
                .region(region)
                .credentialsProvider(credentialsProvider)
                .build();

        // Create log group if not exists
        try {
            client.createLogGroup(CreateLogGroupRequest.builder().logGroupName(logGroupName).build());
        } catch (ResourceAlreadyExistsException e) {
            // Ignore, already exists
        } catch (Exception e) {
            LOGGER.error("Failed to create log group: {}", logGroupName, e);
            return null;
        }

        // Create log stream if not exists
        try {
            client.createLogStream(CreateLogStreamRequest.builder()
                    .logGroupName(logGroupName)
                    .logStreamName(logStreamName)
                    .build());
        } catch (ResourceAlreadyExistsException e) {
            // Ignore, already exists
        } catch (Exception e) {
            LOGGER.error("Failed to create log stream: {} in group: {}", logStreamName, logGroupName, e);
            return null;
        }

        return new CloudWatchAppender(name, filter, layout, ignoreExceptions, Property.EMPTY_ARRAY,
                logGroupName, logStreamName, client);
    }

    @Override
    public void append(LogEvent event) {
        try {
            String message = layout.toSerializable(event).toString();
            if (message.length() > 262144) { // Max event size 256KB
                message = message.substring(0, 262144);
            }
            InputLogEvent logEvent = InputLogEvent.builder()
                    .message(message)
                    .timestamp(event.getTimeMillis())
                    .build();
            if (!queue.offer(logEvent)) {
                LOGGER.warn("Queue full, dropping log event");
            }
        } catch (Exception e) {
            error("Error appending log event", e);
        }
    }

    @Override
    public void start() {
        super.start();
        executor = Executors.newSingleThreadScheduledExecutor();
        executor.scheduleWithFixedDelay(this::flush, 5, 5, TimeUnit.SECONDS); // Flush every 5 seconds
    }

    @Override
    public void stop() {
        super.stop();
        try {
            executor.shutdown();
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
            flush(); // Final flush
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            client.close();
        }
    }

    private void flush() {
        List<InputLogEvent> events = new ArrayList<>(512);
        queue.drainTo(events);
        if (events.isEmpty()) {
            return;
        }

        // Sort by timestamp (required by AWS)
        events.sort(Comparator.comparingLong(InputLogEvent::timestamp));

        // Simple size check (approximate, for demo; in production, calculate exact bytes)
        if (events.size() > 10000) {
            events = events.subList(0, 10000); // Max 10k events per put
        }

        PutLogEventsRequest request = PutLogEventsRequest.builder()
                .logGroupName(logGroupName)
                .logStreamName(logStreamName)
                .logEvents(events)
                .sequenceToken(nextSequenceToken)
                .build();

        boolean success = false;
        int retries = 0;
        while (!success && retries < 3) { // Retry up to 3 times for sequence token issues
            try {
                PutLogEventsResponse response = client.putLogEvents(request);
                nextSequenceToken = response.nextSequenceToken();
                success = true;
            } catch (InvalidSequenceTokenException e) {
                Matcher matcher = SEQUENCE_TOKEN_PATTERN.matcher(e.getMessage());
                if (matcher.find()) {
                    nextSequenceToken = matcher.group(1);
                    request = request.toBuilder().sequenceToken(nextSequenceToken).build();
                } else {
                    error("Invalid sequence token and could not parse expected token", e);
                    break;
                }
                retries++;
            } catch (Exception e) {
                error("Error putting log events", e);
                break;
            }
        }
    }
}
