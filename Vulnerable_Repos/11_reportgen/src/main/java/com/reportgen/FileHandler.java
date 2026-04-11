package com.reportgen;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class FileHandler {

    private static final Logger logger = LoggerFactory.getLogger(FileHandler.class);

    @Value("${report.template.dir:/opt/reportgen/templates}")
    private String baseDir;

    public String loadTemplate(String templateName) throws IOException {
        logger.info("Loading template: {}", templateName);

        File templateFile = new File(baseDir + "/" + templateName);
        String content = Files.readString(templateFile.toPath());

        logger.info("Template loaded successfully ({} chars)", content.length());
        return content;
    }

    public List<String> listAvailableTemplates() {
        File directory = new File(baseDir);
        String[] fileNames = directory.list((dir, name) ->
                name.endsWith(".html") || name.endsWith(".txt") || name.endsWith(".xml"));

        if (fileNames == null) {
            return List.of();
        }

        return Arrays.stream(fileNames)
                .sorted()
                .collect(Collectors.toList());
    }

    public void saveGeneratedReport(String reportName, String content) throws IOException {
        Path outputDir = Path.of(baseDir, "output");
        Files.createDirectories(outputDir);

        Path reportPath = outputDir.resolve(reportName);
        Files.writeString(reportPath, content);
        logger.info("Report saved to {}", reportPath);
    }

    public long getTemplateSize(String templateName) {
        File templateFile = new File(baseDir + "/" + templateName);
        return templateFile.length();
    }
}
