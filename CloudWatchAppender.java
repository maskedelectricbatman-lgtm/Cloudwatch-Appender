import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.logs.AWSLogs;
import com.amazonaws.services.logs.AWSLogsClientBuilder;
import com.amazonaws.services.logs.model.DescribeLogStreamsRequest;
import com.amazonaws.services.logs.model.DescribeLogStreamsResult;
import com.amazonaws.services.logs.model.InputLogEvent;
import com.amazonaws.services.logs.model.PutLogEventsRequest;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.Core;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.core.layout.PatternLayout;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Custom Log4j2 Appender to send logs to AWS CloudWatch.
 * Requires AWS SDK for Java 1.x (compatible with Java 8).
 */
@Plugin(name = "CloudWatchAppender", category = Core.CATEGORY_NAME, elementType = Appender.ELEMENT_TYPE)
public class CloudWatchAppender extends org.apache.logging.log4j.core.appender.AbstractAppender {

    private final String logGroupName;
    private final String logStreamName;
    private final Regions region;
    private final AWSLogs client;
    private volatile String sequenceToken;

    protected CloudWatchAppender(String name, String accessKeyId, String secretAccessKey, String logGroupName,
                                String logStreamName, String regionName, org.apache.logging.log4j.core.Filter filter,
                                org.apache.logging.log4j.core.Layout<? extends Serializable> layout, boolean ignoreExceptions) {
        super(name, filter, layout, ignoreExceptions, null);
        this.logGroupName = logGroupName;
        this.logStreamName = logStreamName;
        this.region = Regions.fromName(regionName.toLowerCase().replace("_", "-")); // e.g., US_EAST_1 -> us-east-1
        this.client = AWSLogsClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials(accessKeyId, secretAccessKey)))
                .withRegion(this.region)
                .build();
        this.sequenceToken = getSequenceToken();
    }

    @PluginFactory
    public static CloudWatchAppender createAppender(
            @PluginAttribute("name") String name,
            @PluginAttribute("accessKeyId") String accessKeyId,
            @PluginAttribute("secretAccessKey") String secretAccessKey,
            @PluginAttribute("logGroupName") String logGroupName,
            @PluginAttribute("logStreamName") String logStreamName,
            @PluginAttribute("region") String region,
            @PluginElement("Filter") org.apache.logging.log4j.core.Filter filter,
            @PluginElement("Layout") org.apache.logging.log4j.core.Layout<? extends Serializable> layout,
            @PluginAttribute("ignoreExceptions") boolean ignoreExceptions) {
        if (name == null) {
            LOGGER.error("No name provided for CloudWatchAppender");
            return null;
        }
        if (layout == null) {
            layout = PatternLayout.createDefaultLayout();
        }
        return new CloudWatchAppender(name, accessKeyId, secretAccessKey, logGroupName, logStreamName, region, filter, layout, ignoreExceptions);
    }

    @Override
    public void append(LogEvent event) {
        try {
            // Format the log event using the configured layout
            String message = new String(getLayout().toByteArray(event));

            // Create CloudWatch log event
            InputLogEvent logEvent = new InputLogEvent()
                    .withMessage(message)
                    .withTimestamp(event.getTimeMillis());

            List<InputLogEvent> logEvents = new ArrayList<>();
            logEvents.add(logEvent);

            // Create PutLogEvents request
            PutLogEventsRequest request = new PutLogEventsRequest()
                    .withLogGroupName(logGroupName)
                    .withLogStreamName(logStreamName)
                    .withLogEvents(logEvents)
                    .withSequenceToken(sequenceToken);

            // Send log to CloudWatch
            synchronized (this) {
                try {
                    client.putLogEvents(request);
                    // Update sequence token (optional in newer SDKs but included for compatibility)
                    sequenceToken = getSequenceToken();
                } catch (Exception e) {
                    if (!isIgnoreExceptions()) {
                        throw e;
                    }
                    LOGGER.error("Failed to send log to CloudWatch: {}", e.getMessage());
                }
            }
        } catch (Exception e) {
            if (!isIgnoreExceptions()) {
                throw new RuntimeException("Error appending log to CloudWatch", e);
            }
            LOGGER.error("Error appending log to CloudWatch: {}", e.getMessage());
        }
    }

    private String getSequenceToken() {
        try {
            DescribeLogStreamsRequest describeRequest = new DescribeLogStreamsRequest()
                    .withLogGroupName(logGroupName)
                    .withLogStreamNamePrefix(logStreamName);
            DescribeLogStreamsResult result = client.describeLogStreams(describeRequest);
            return result.getLogStreams().stream()
                    .filter(stream -> stream.getLogStreamName().equals(logStreamName))
                    .findFirst()
                    .map(stream -> stream.getUploadSequenceToken())
                    .orElse(null); // Null is valid for first log event in some cases
        } catch (Exception e) {
            LOGGER.error("Error retrieving sequence token: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public void stop() {
        super.stop();
        client.shutdown();
    }
}
