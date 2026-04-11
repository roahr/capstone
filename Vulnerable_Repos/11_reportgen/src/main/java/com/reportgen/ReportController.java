package com.reportgen;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.util.Map;

@RestController
@RequestMapping("/api/reports")
public class ReportController {

    @Autowired
    private LdapLookup ldapLookup;

    @Autowired
    private FileHandler fileHandler;

    @Autowired
    private TemplateEngine templateEngine;

    @PostMapping("/generate")
    public ResponseEntity<Map<String, Object>> generateReport(
            @RequestParam String templateName,
            @RequestParam String authorUsername,
            @RequestParam(required = false) Map<String, String> parameters) {

        try {
            Map<String, String> userDetails = ldapLookup.getUserDetails(authorUsername);
            String templateContent = fileHandler.loadTemplate(templateName);
            String rendered = templateEngine.render(templateContent, userDetails, parameters);

            return ResponseEntity.ok(Map.of(
                    "status", "generated",
                    "author", userDetails.getOrDefault("displayName", authorUsername),
                    "content", rendered,
                    "templateUsed", templateName
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/user-info")
    public ResponseEntity<Map<String, String>> lookupUser(
            @RequestParam String username) {
        try {
            Map<String, String> details = ldapLookup.getUserDetails(username);
            return ResponseEntity.ok(details);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/restore")
    public ResponseEntity<Map<String, Object>> restoreState(
            @RequestParam("stateFile") MultipartFile stateFile) {
        try {
            InputStream stream = stateFile.getInputStream();
            Object state = templateEngine.restoreReportState(stream);
            return ResponseEntity.ok(Map.of(
                    "status", "restored",
                    "state", state.toString()
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "State restore failed: " + e.getMessage()));
        }
    }
}
