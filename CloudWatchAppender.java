// CloudWatchAppender.java
package com.example.logging;

import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.Core;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.*;

import java.io.Serializable;
import java.time.Instant;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.List;
import java.util.ArrayList;

@Plugin(name = "CloudWatch", category = Core.CATEGORY_NAME, elementType = Appender.ELEMENT_TYPE, printObject = true)
public class CloudWatchAppender extends AbstractAppender {

    private final CloudWatchLogsClient cloudWatchClient;
    private final String logGroupName;
    private final String logStreamName;
    private final BlockingQueue<InputLogEvent> logQueue;
    private final LogEventProcessor logProcessor;
    private final AtomicBoolean started = new AtomicBoolean(false);

    private CloudWatchAppender(String name, Filter filter, Layout<? extends Serializable> layout,
                              boolean ignoreExceptions, CloudWatchLogsClient client,
                              String logGroupName, String logStreamName) {
        super(name, filter, layout, ignoreExceptions);
        this.cloudWatchClient = client;
        this.logGroupName = logGroupName;
        this.logStreamName = logStreamName;
        this.logQueue = new LinkedBlockingQueue<>();
        this.logProcessor = new LogEventProcessor();
    }

    @Override
    public void start() {
        super.start();
        if (started.compareAndSet(false, true)) {
            initializeCloudWatchResources();
            logProcessor.start();
        }
    }

    @Override
    public void stop() {
        if (started.compareAndSet(true, false)) {
            logProcessor.stop();
            super.stop();
        }
    }

    @Override
    public void append(LogEvent event) {
        if (started.get()) {
            String message = getLayout().toSerializable(event).toString();
            InputLogEvent logEvent = InputLogEvent.builder()
                    .timestamp(event.getTimeMillis())
                    .message(message)
                    .build();
            
            if (!logQueue.offer(logEvent)) {
                System.err.println("CloudWatch log queue is full, dropping log message");
            }
        }
    }

    private void initializeCloudWatchResources() {
        try {
            // Create log group if it doesn't exist
            try {
                DescribeLogGroupsResponse response = cloudWatchClient.describeLogGroups(
                    DescribeLogGroupsRequest.builder()
                        .logGroupNamePrefix(logGroupName)
                        .build());
                
                boolean groupExists = response.logGroups().stream()
                    .anyMatch(group -> group.logGroupName().equals(logGroupName));
                
                if (!groupExists) {
                    cloudWatchClient.createLogGroup(CreateLogGroupRequest.builder()
                            .logGroupName(logGroupName)
                            .build());
                }
            } catch (Exception e) {
                try {
                    cloudWatchClient.createLogGroup(CreateLogGroupRequest.builder()
                            .logGroupName(logGroupName)
                            .build());
                } catch (Exception createException) {
                    System.err.println("Failed to create log group: " + createException.getMessage());
                }
            }

            // Create log stream if it doesn't exist
            try {
                DescribeLogStreamsResponse response = cloudWatchClient.describeLogStreams(
                    DescribeLogStreamsRequest.builder()
                        .logGroupName(logGroupName)
                        .logStreamNamePrefix(logStreamName)
                        .build());
                
                boolean streamExists = response.logStreams().stream()
                    .anyMatch(stream -> stream.logStreamName().equals(logStreamName));
                
                if (!streamExists) {
                    cloudWatchClient.createLogStream(CreateLogStreamRequest.builder()
                            .logGroupName(logGroupName)
                            .logStreamName(logStreamName)
                            .build());
                }
            } catch (Exception e) {
                try {
                    cloudWatchClient.createLogStream(CreateLogStreamRequest.builder()
                            .logGroupName(logGroupName)
                            .logStreamName(logStreamName)
                            .build());
                } catch (Exception createException) {
                    System.err.println("Failed to create log stream: " + createException.getMessage());
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to initialize CloudWatch resources: " + e.getMessage());
        }
    }

    @PluginFactory
    public static CloudWatchAppender createAppender(
            @PluginAttribute("name") String name,
            @PluginAttribute("region") String region,
            @PluginAttribute("logGroupName") String logGroupName,
            @PluginAttribute("logStreamName") String logStreamName,
            @PluginAttribute("accessKey") String accessKey,
            @PluginAttribute("secretKey") String secretKey,
            @PluginAttribute("useRole") String useRole,
            @PluginAttribute("ignoreExceptions") boolean ignoreExceptions,
            @PluginElement("Layout") Layout<? extends Serializable> layout,
            @PluginElement("Filter") Filter filter) {

        if (name == null) {
            LOGGER.error("No name provided for CloudWatchAppender");
            return null;
        }

        if (region == null) {
            region = "us-east-1";
        }

        if (logGroupName == null) {
            LOGGER.error("No log group name provided for CloudWatchAppender");
            return null;
        }

        if (logStreamName == null) {
            logStreamName = "default-stream-" + Instant.now().getEpochSecond();
        }

        CloudWatchLogsClient client = createCloudWatchClient(region, accessKey, secretKey, useRole);
        
        return new CloudWatchAppender(name, filter, layout, ignoreExceptions, 
                                    client, logGroupName, logStreamName);
    }

    private static CloudWatchLogsClient createCloudWatchClient(String region, String accessKey, 
                                                             String secretKey, String useRole) {
        Region awsRegion = Region.of(region);
        
        AwsCredentialsProvider credentialsProvider;
        
        // Determine authentication method
        if (useRole != null && useRole.equalsIgnoreCase("true")) {
            // Use IAM role (default credentials provider chain)
            credentialsProvider = DefaultCredentialsProvider.create();
            System.out.println("Using IAM role for CloudWatch authentication");
        } else if (accessKey != null && secretKey != null) {
            // Use explicit credentials
            credentialsProvider = StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(accessKey, secretKey));
            System.out.println("Using explicit credentials for CloudWatch authentication");
        } else {
            // Fallback to default credentials provider
            credentialsProvider = DefaultCredentialsProvider.create();
            System.out.println("Using default credentials provider for CloudWatch authentication");
        }

        return CloudWatchLogsClient.builder()
                .region(awsRegion)
                .credentialsProvider(credentialsProvider)
                .build();
    }

    private class LogEventProcessor {
        private Thread processorThread;
        private final AtomicBoolean running = new AtomicBoolean(false);
        private String sequenceToken = null;

        public void start() {
            if (running.compareAndSet(false, true)) {
                processorThread = new Thread(this::processLogs, "CloudWatch-LogProcessor");
                processorThread.setDaemon(true);
                processorThread.start();
            }
        }

        public void stop() {
            if (running.compareAndSet(true, false)) {
                if (processorThread != null) {
                    processorThread.interrupt();
                    try {
                        processorThread.join(5000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                // Flush remaining logs
                flushLogs();
            }
        }

        private void processLogs() {
            List<InputLogEvent> batch = new ArrayList<>();
            
            while (running.get() || !logQueue.isEmpty()) {
                try {
                    InputLogEvent event = logQueue.poll(1, TimeUnit.SECONDS);
                    if (event != null) {
                        batch.add(event);
                        
                        // Send batch when it reaches certain size or after timeout
                        if (batch.size() >= 1000 || shouldFlushBatch(batch)) {
                            sendLogBatch(batch);
                            batch.clear();
                        }
                    } else if (!batch.isEmpty()) {
                        // Timeout occurred, flush current batch
                        sendLogBatch(batch);
                        batch.clear();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    System.err.println("Error processing CloudWatch logs: " + e.getMessage());
                }
            }
        }

        private boolean shouldFlushBatch(List<InputLogEvent> batch) {
            if (batch.isEmpty()) return false;
            
            // Calculate approximate batch size (1MB limit)
            int totalSize = batch.stream()
                    .mapToInt(event -> event.message().length() + 26) // 26 bytes overhead per event
                    .sum();
            
            return totalSize > 900000; // Leave some buffer below 1MB limit
        }

        private void sendLogBatch(List<InputLogEvent> events) {
            if (events.isEmpty()) return;
            
            try {
                // Sort events by timestamp (required by CloudWatch)
                events.sort((a, b) -> Long.compare(a.timestamp(), b.timestamp()));
                
                PutLogEventsRequest.Builder requestBuilder = PutLogEventsRequest.builder()
                        .logGroupName(logGroupName)
                        .logStreamName(logStreamName)
                        .logEvents(events);
                
                if (sequenceToken != null) {
                    requestBuilder.sequenceToken(sequenceToken);
                }
                
                PutLogEventsResponse response = cloudWatchClient.putLogEvents(requestBuilder.build());
                sequenceToken = response.nextSequenceToken();
                
            } catch (InvalidSequenceTokenException e) {
                // Handle sequence token mismatch
                sequenceToken = e.expectedSequenceToken();
                if (sequenceToken != null) {
                    sendLogBatch(events); // Retry with correct token
                }
            } catch (DataAlreadyAcceptedException e) {
                // Log events were already accepted, update sequence token
                sequenceToken = e.expectedSequenceToken();
            } catch (Exception e) {
                System.err.println("Failed to send log batch to CloudWatch: " + e.getMessage());
            }
        }

        private void flushLogs() {
            List<InputLogEvent> remainingLogs = new ArrayList<>();
            logQueue.drainTo(remainingLogs);
            if (!remainingLogs.isEmpty()) {
                sendLogBatch(remainingLogs);
            }
        }
    }
}
