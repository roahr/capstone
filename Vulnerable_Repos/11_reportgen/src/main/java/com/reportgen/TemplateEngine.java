package com.reportgen;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class TemplateEngine {

    private static final Logger logger = LoggerFactory.getLogger(TemplateEngine.class);
    private static final Pattern PLACEHOLDER_PATTERN = Pattern.compile("\\$\\{(\\w+)}");

    public String render(String template, Map<String, String> userDetails,
                         Map<String, String> extraParams) {

        Map<String, String> allVariables = new HashMap<>();
        if (userDetails != null) {
            allVariables.putAll(userDetails);
        }
        if (extraParams != null) {
            allVariables.putAll(extraParams);
        }
        allVariables.put("generatedAt",
                LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

        StringBuffer output = new StringBuffer();
        Matcher matcher = PLACEHOLDER_PATTERN.matcher(template);
        while (matcher.find()) {
            String key = matcher.group(1);
            String replacement = allVariables.getOrDefault(key, matcher.group(0));
            matcher.appendReplacement(output, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(output);

        logger.info("Template rendered with {} variables", allVariables.size());
        return output.toString();
    }

    public Object restoreReportState(InputStream stateStream) throws Exception {
        logger.info("Restoring report state from saved snapshot");

        StateLoader loader = new StateLoader(stateStream);
        return loader.loadState();
    }

    private static class StateLoader {
        private final InputStream source;

        StateLoader(InputStream source) {
            this.source = source;
        }

        Object loadState() throws Exception {
            ObjectInputStream objectStream = new ObjectInputStream(source);
            Object state = objectStream.readObject();
            objectStream.close();
            return state;
        }
    }

    public Map<String, Object> getEngineInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("version", "2.0.1");
        info.put("placeholderPattern", PLACEHOLDER_PATTERN.pattern());
        info.put("supportsHtml", true);
        return info;
    }
}
