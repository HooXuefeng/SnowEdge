package burp;

import javax.swing.*;
import java.awt.Component;
import java.awt.GridLayout;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("SnowEdge");
        callbacks.registerContextMenuFactory(this);
        callbacks.printOutput("SnowEdge extension loaded. Requests are only sent to the configured local Workspace API.");
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();
        JMenuItem send = new JMenuItem("Send to SnowEdge");
        send.addActionListener(e -> sendSelected(invocation));
        items.add(send);

        JMenuItem configure = new JMenuItem("Configure SnowEdge...");
        configure.addActionListener(e -> configure());
        items.add(configure);
        return items;
    }

    private void configure() {
        JTextField base = new JTextField(setting("base_url", "http://127.0.0.1:8000"));
        JTextField project = new JTextField(setting("project_id", ""));
        JPasswordField token = new JPasswordField(setting("token", ""));

        JPanel panel = new JPanel(new GridLayout(0, 1, 4, 4));
        panel.add(new JLabel("Workspace Base URL"));
        panel.add(base);
        panel.add(new JLabel("Project ID"));
        panel.add(project);
        panel.add(new JLabel("Integration Token"));
        panel.add(token);

        int result = JOptionPane.showConfirmDialog(null, panel, "SnowEdge", JOptionPane.OK_CANCEL_OPTION);
        if (result == JOptionPane.OK_OPTION) {
            callbacks.saveExtensionSetting("base_url", trimSlash(base.getText().trim()));
            callbacks.saveExtensionSetting("project_id", project.getText().trim());
            callbacks.saveExtensionSetting("token", new String(token.getPassword()));
            callbacks.printOutput("SnowEdge extension settings saved.");
        }
    }

    private void sendSelected(IContextMenuInvocation invocation) {
        String base = setting("base_url", "");
        String project = setting("project_id", "");
        String token = setting("token", "");
        if (base.isEmpty() || project.isEmpty() || token.isEmpty()) {
            configure();
            base = setting("base_url", "");
            project = setting("project_id", "");
            token = setting("token", "");
            if (base.isEmpty() || project.isEmpty() || token.isEmpty()) {
                return;
            }
        }

        IHttpRequestResponse[] selected = invocation.getSelectedMessages();
        if (selected == null || selected.length == 0) {
            JOptionPane.showMessageDialog(null, "No request is selected.", "SnowEdge", JOptionPane.WARNING_MESSAGE);
            return;
        }

        int ok = 0;
        List<String> errors = new ArrayList<>();
        for (IHttpRequestResponse message : selected) {
            if (message == null || message.getRequest() == null || message.getHttpService() == null) {
                continue;
            }
            try {
                String raw = new String(message.getRequest(), StandardCharsets.ISO_8859_1);
                String protocol = message.getHttpService().getProtocol();
                String name = "Burp → Workspace · " + helpers.analyzeRequest(message).getMethod();
                sendOne(base, project, token, protocol, name, raw);
                ok++;
            } catch (Exception ex) {
                errors.add(ex.getClass().getSimpleName() + ": " + ex.getMessage());
                callbacks.printError("Send failed: " + ex);
            }
        }

        String text = ok + " request(s) saved to SnowEdge.";
        if (!errors.isEmpty()) {
            text += "\n" + errors.size() + " failed. See Extender output/errors.";
        }
        JOptionPane.showMessageDialog(null, text, "SnowEdge", errors.isEmpty() ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE);
    }

    private void sendOne(String base, String project, String token, String scheme, String name, String raw) throws Exception {
        URL url = new URL(trimSlash(base) + "/api/projects/" + project + "/burp/send");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(3000);
        connection.setReadTimeout(5000);
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        connection.setRequestProperty("X-SnowEdge-Token", token);

        String json = "{"
                + "\"scheme\":\"" + escape(scheme) + "\","
                + "\"name\":\"" + escape(name) + "\","
                + "\"raw_request\":\"" + escape(raw) + "\""
                + "}";
        byte[] data = json.getBytes(StandardCharsets.UTF_8);
        connection.setFixedLengthStreamingMode(data.length);
        try (OutputStream out = connection.getOutputStream()) {
            out.write(data);
        }
        int status = connection.getResponseCode();
        if (status < 200 || status >= 300) {
            throw new IllegalStateException("Workspace returned HTTP " + status);
        }
        connection.disconnect();
    }

    private String setting(String key, String fallback) {
        String value = callbacks.loadExtensionSetting(key);
        return value == null ? fallback : value;
    }

    private static String trimSlash(String value) {
        while (value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        return value;
    }

    private static String escape(String value) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\': b.append("\\\\"); break;
                case '"': b.append("\\\""); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int)c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.toString();
    }
}
