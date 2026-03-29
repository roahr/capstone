/**
 * UserPortal — User Management REST Controller
 *
 * Handles HTTP endpoints for user operations:
 *   - User search and lookup
 *   - Data import/export
 *   - Profile management
 *
 * Spring MVC-style controller with JSON and HTML response types.
 */
package com.userportal.controller;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.userportal.model.User;
import com.userportal.service.DatabaseHelper;
import com.userportal.service.UserService;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private static final Logger logger = Logger.getLogger(UserController.class.getName());
    private static final String CONFIG_CACHE_PATH = "/etc/app/config.ser";

    @Autowired
    private UserService userService;

    @Autowired
    private DatabaseHelper databaseHelper;

    /**
     * List all registered users with optional pagination.
     */
    @GetMapping
    public ResponseEntity<List<User>> listUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size) {
        List<User> users = userService.findAll(page, size);
        return ResponseEntity.ok(users);
    }

    // -----------------------------------------------------------------------
    // TRUE POSITIVE: CWE-502 Unsafe Deserialization
    // The incoming byte array (user-controlled) is deserialized directly via
    // ObjectInputStream without any filtering or type-checking, allowing
    // arbitrary code execution through crafted serialized payloads.
    // -----------------------------------------------------------------------
    /**
     * Import user data from a serialized Java object payload.
     * Used by the legacy desktop client for bulk user uploads.
     *
     * @param data Serialized byte array from the client
     * @return imported user record
     */
    @PostMapping(value = "/import", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<User> importUserData(@RequestBody byte[] data) {
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            User imported = (User) ois.readObject();
            ois.close();
            logger.info("Imported user: " + imported.getUsername());
            userService.save(imported);
            return ResponseEntity.status(HttpStatus.CREATED).body(imported);
        } catch (Exception e) {
            logger.warning("Import failed: " + e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    // -----------------------------------------------------------------------
    // TRUE POSITIVE: CWE-79 Cross-Site Scripting (Reflected XSS)
    // The query parameter is embedded directly into an HTML response string
    // without any output encoding, allowing injection of arbitrary HTML/JS.
    // -----------------------------------------------------------------------
    /**
     * Search users by name and return an HTML snippet for the legacy
     * server-rendered search page.
     *
     * @param query search term from the user
     * @return HTML fragment with search results
     */
    @GetMapping(value = "/search", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> searchUsers(@RequestParam String query) {
        List<User> results = databaseHelper.findUsersByName(query);
        StringBuilder html = new StringBuilder();
        html.append("<div>Search results for: " + query + "</div>");
        html.append("<ul>");
        for (User u : results) {
            html.append("<li>").append(u.getUsername()).append("</li>");
        }
        html.append("</ul>");
        return ResponseEntity.ok(html.toString());
    }

    // -----------------------------------------------------------------------
    // FALSE POSITIVE #9: CWE-502 — ObjectInputStream from trusted local file
    // (Contextual tier, Graph resolves)
    // SAST will flag the ObjectInputStream usage, but the data source is a
    // hard-coded local file path (/etc/app/config.ser) that is not influenced
    // by user input. A graph/dataflow analysis tracing the input source would
    // show no taint from any external entry point.
    // -----------------------------------------------------------------------
    /**
     * Load cached application configuration from the local serialized file.
     * This is called once at startup to restore persisted settings.
     *
     * @return the cached configuration map, or null if not available
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> loadCachedConfig() {
        File configFile = new File(CONFIG_CACHE_PATH);
        if (!configFile.exists()) {
            logger.info("No cached config found at " + CONFIG_CACHE_PATH);
            return null;
        }
        try {
            FileInputStream fis = new FileInputStream(configFile);
            ObjectInputStream ois = new ObjectInputStream(fis);
            Map<String, Object> config = (Map<String, Object>) ois.readObject();
            ois.close();
            fis.close();
            logger.info("Loaded cached config with " + config.size() + " entries");
            return config;
        } catch (Exception e) {
            logger.warning("Failed to load cached config: " + e.getMessage());
            return null;
        }
    }

    /**
     * Health-check endpoint.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("status", "ok", "service", "user-portal"));
    }
}
