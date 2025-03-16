import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

import javafx.scene.chart.LineChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

public class IDS_GUI extends Application {
    private TextArea logArea = new TextArea();
    private LineChart<Number, Number> trafficChart;
    private XYChart.Series<Number, Number> series;
    private int time = 0;
    private int packetCount = 0;
    private static final int MAX_DATA_POINTS = 30; // Limit to 50 data points

    private ExecutorService executorService = Executors.newSingleThreadExecutor();
    private Thread portScanThread; // Thread to run port scan detection
    private Thread bruteThread; // Thread for brute detection

    // Store the handle so we can break the loop later
    private PcapHandle handle;

    long timeDif = System.currentTimeMillis() / 1000;

    private final ConcurrentHashMap<String, ConcurrentLinkedQueue<Long>> failedLoginAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ConcurrentLinkedQueue<Long>> synTimestamps = new ConcurrentHashMap<>();
    private final long WINDOW_MILLIS = 10000; // 10 seconds window
    private final int THRESHOLD = 15; // More than 15 SYNs in the window triggers alert


    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Network Intrusion Detection System");
        Label titleLabel = new Label("Real-Time Network Security Monitor");
        Button startButton = new Button("Start Monitoring");
        Button stopButton = new Button("Stop Monitoring");
        setupChart();
        startButton.setOnAction(e -> {
            executorService = Executors.newSingleThreadExecutor();
            executorService.submit(this::capturePackets);
            startPortScanDetectionThread();


        });
        stopButton.setOnAction(e -> stopCapturing());



        // Add the chart to the layout so it's visible
        VBox layout = new VBox(10, titleLabel, startButton, stopButton, logArea, trafficChart );
        Scene scene = new Scene(layout, 600, 600);

        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void capturePackets() {
        try {
            ExecutorService executorService = Executors.newSingleThreadExecutor();
            PcapNetworkInterface nif = Pcaps.findAllDevs().get(0);
            handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);
            handle.loop(-1, (PacketListener) packet -> {
                packetCount++;
                if (packet.contains(TcpPacket.class) && packet.contains(IpV4Packet.class)) {
                    TcpPacket tcpPacket = packet.get(TcpPacket.class);
                    IpV4Packet ipPacket = packet.get(IpV4Packet.class);
                    String srcIp = ipPacket.getHeader().getSrcAddr().toString();
                    int destPort = tcpPacket.getHeader().getDstPort().valueAsInt();

                    // For Port Scan Detection: Register SYN events (if SYN flag is set and no ACK)
                    if (tcpPacket.getHeader().getSyn() && !tcpPacket.getHeader().getAck()) {
                        registerSynEvent(srcIp);
                    }

                    // For Brute Force Detection: Monitor connection attempts on sensitive ports
                    if (destPort == 22 || destPort == 3389 || destPort == 21) {
                        detectBruteForce(srcIp, destPort);
                    }
                }
                Platform.runLater(() -> {
                    long currentTimeInSeconds = System.currentTimeMillis() / 1000;
                    if(currentTimeInSeconds>timeDif){
                        timeDif = currentTimeInSeconds;
                        updateTrafficChart(packetCount);
                        packetCount=0;
                    }

                    logArea.appendText("Captured Packet: " + packet.toString() + "\n");

                    // Prevent logArea from growing too large
                    if (logArea.getText().length() > 5000) {
                        logArea.deleteText(0, 1000);
                    }
                });
            });
        } catch (Exception e) {
            Platform.runLater(() -> logArea.appendText("Error: " + e.getMessage() + "\n"));
        }
    }

    private void stopCapturing() {
        try {
            if (handle != null && handle.isOpen()) {
                handle.breakLoop();  // This stops the packet loop
                handle.close();      // Close the handle cleanly
                Platform.runLater(() -> logArea.appendText("Monitoring Stopped.\n"));
            }
            executorService.shutdownNow();
            if (portScanThread != null && portScanThread.isAlive()) {
                portScanThread.interrupt();
            }
        } catch (Exception e) {
            Platform.runLater(() -> logArea.appendText("Error stopping capture: " + e.getMessage() + "\n"));
        }
    }

    private void registerSynEvent(String srcIp) {
        long currentTimestamp = System.currentTimeMillis();
        synTimestamps.computeIfAbsent(srcIp, k -> new ConcurrentLinkedQueue<>()).add(currentTimestamp);
    }

    // Dedicated thread function to check for port scans periodically
    private void startPortScanDetectionThread() {
        portScanThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                checkForPortScan();
                try {
                    Thread.sleep(1000); // Wait 1 second between checks
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
        portScanThread.start();
    }



    private void checkForPortScan() {
        long currentTimestamp = System.currentTimeMillis();
        for (String srcIp : synTimestamps.keySet()) {
            ConcurrentLinkedQueue<Long> timestamps = synTimestamps.get(srcIp);
            while (!timestamps.isEmpty() && currentTimestamp - timestamps.peek() > WINDOW_MILLIS) {
                timestamps.poll();
            }
            if (timestamps.size() > THRESHOLD) {
                Platform.runLater(() -> {
                    logArea.appendText("[ALERT] Port scan detected from " + srcIp + "\n");
                    showAlert("Port Scan Alert", "Suspicious activity detected from " + srcIp);

                });
                timestamps.clear();
            }
        }
    }

    private void detectBruteForce(String srcIp, int destPort) {
        long currentTimestamp = System.currentTimeMillis();
        failedLoginAttempts.computeIfAbsent(srcIp, k -> new ConcurrentLinkedQueue<>()).add(currentTimestamp);

        // Remove timestamps older than the brute force window
        failedLoginAttempts.get(srcIp).removeIf(timestamp -> currentTimestamp - timestamp > WINDOW_MILLIS);

        if (failedLoginAttempts.get(srcIp).size() > THRESHOLD) {
            Platform.runLater(() -> {
                logArea.appendText("[ALERT] Possible brute-force attack from " + srcIp + " on port " + destPort + "\n");
                showAlert("Brute-Force Alert", "Multiple failed attempts from " + srcIp);
            });
            failedLoginAttempts.get(srcIp).clear(); // Reset count after alert
        }
    }


    private void showAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private void setupChart() {
        NumberAxis xAxis = new NumberAxis();
        NumberAxis yAxis = new NumberAxis();
        xAxis.setLabel("Time (seconds)");
        yAxis.setLabel("Packets Captured");

        trafficChart = new LineChart<>(xAxis, yAxis);
        series = new XYChart.Series<>();
        series.setName("Network Traffic");
        trafficChart.getData().add(series);
    }

    private void updateTrafficChart(int packetCount) {
        time++;
        Platform.runLater(() -> {
            if (series.getData().size() > MAX_DATA_POINTS) {
                series.getData().remove(0); // Remove the oldest data point
            }
            series.getData().add(new XYChart.Data<>(time, packetCount));
        });
    }

    public static void main(String[] args) {
        launch(args);
    }
}
