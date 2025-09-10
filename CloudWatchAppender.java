package com;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.logs.AWSLogs;
import com.amazonaws.services.logs.AWSLogsClientBuilder;
import com.amazonaws.services.logs.model.DescribeLogStreamsRequest;
import com.amazonaws.services.logs.model.DescribeLogStreamsResult;
import com.amazonaws.services.logs.model.InputLogEvent;
import com.amazonaws.services.logs.model.PutLogEventsRequest;
import com.amazonaws.services.logs.model.PutLogEventsResult;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.Core;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Custom Log4j2 Appender to send logs to AWS CloudWatch.
 * Compatible with Java 8 and Java 17, using AWS SDK 1.x.
 */
@Plugin(name = "CloudWatchAppender", category = Core.CATEGORY_NAME, elementType = Appender.ELEMENT_TYPE)
public class CloudWatchAppender extends org.apache.logging.log4j.core.appender.AbstractAppender {

    private static final Logger LOGGER = LogManager.getLogger(CloudWatchAppender.class);

    private final String logGroupName;
    private final String logStreamName;
    private final Regions region;
    private final AWSLogs client;
    private volatile String sequenceToken;
    private final boolean ignoreExceptions;

    protected CloudWatchAppender(String name, String accessKeyId, String secretAccessKey, String logGroupName,
                                String logStreamName, String regionName, org.apache.logging.log4j.core.Filter filter,
                                org.apache.logging.log4j.core.Layout<? extends Serializable> layout, boolean ignoreExceptions) {
        super(name, filter, layout, ignoreExceptions, null);
        this.logGroupName = logGroupName;
        this.logStreamName = logStreamName;
        this.region = Regions.fromName(regionName.toLowerCase().replace("_", "-"));
        this.client = AWSLogsClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials(accessKeyId, secretAccessKey)))
                .withRegion(this.region)
                .build();
        this.sequenceToken = getSequenceToken();
        this.ignoreExceptions = ignoreExceptions;
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
            @PluginAttribute(value = "ignoreExceptions", defaultBoolean = true) boolean ignoreExceptions) {
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
            String message = new String(getLayout().toByteArray(event));
            LOGGER.debug("Attempting to send log to CloudWatch: {}", message);

            InputLogEvent logEvent = new InputLogEvent()
                    .withMessage(message)
                    .withTimestamp(event.getTimeMillis());

            List<InputLogEvent> logEvents = new ArrayList<>();
            logEvents.add(logEvent);

            PutLogEventsRequest request = new PutLogEventsRequest()
                    .withLogGroupName(logGroupName)
                    .withLogStreamName(logStreamName)
                    .withLogEvents(logEvents)
                    .withSequenceToken(sequenceToken != null ? sequenceToken : "");

            synchronized (this) {
                try {
                    PutLogEventsResult result = client.putLogEvents(request);
                    sequenceToken = result.getNextSequenceToken();
                    LOGGER.debug("Successfully sent log to CloudWatch. Next token: {}", sequenceToken);
                } catch (Exception e) {
                    LOGGER.error("Failed to send log to CloudWatch: {}", e.getMessage(), e);
                    if (!ignoreExceptions) {
                        throw e;
                    }
                    sequenceToken = getSequenceToken();
                }
            }
        } catch (Exception e) {
            LOGGER.error("Error in append method: {}", e.getMessage(), e);
            if (!ignoreExceptions) {
                throw new RuntimeException("Error appending log to CloudWatch", e);
            }
        }
    }

    private String getSequenceToken() {
        try {
            var describeRequest = new DescribeLogStreamsRequest()
                    .withLogGroupName(logGroupName)
                    .withLogStreamNamePrefix(logStreamName);
            DescribeLogStreamsResult result = client.describeLogStreams(describeRequest);
            String token = result.getLogStreams().stream()
                    .filter(stream -> stream.getLogStreamName().equals(logStreamName))
                    .findFirst()
                    .map(stream -> stream.getUploadSequenceToken())
                    .orElse(null);
            LOGGER.debug("Retrieved sequence token: {}", token != null ? "present" : "null");
            return token;
        } catch (Exception e) {
            LOGGER.error("Error retrieving sequence token: {}", e.getMessage(), e);
            return null;
        }
    }

    @Override
    public void stop() {
        super.stop();
        client.shutdown();
    }
}
