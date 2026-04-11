package com.inventory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/items")
public class InventoryController {

    @Autowired
    private InventoryService inventoryService;

    @Autowired
    private XmlImporter xmlImporter;

    @GetMapping("/search")
    public ResponseEntity<List<Map<String, Object>>> searchItems(
            @RequestParam String query) {

        List<Map<String, Object>> results = inventoryService.findItemsByName(query);

        if (results.isEmpty()) {
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.ok(results);
    }

    @PostMapping("/import")
    public ResponseEntity<Map<String, Object>> importFromXml(
            @RequestParam("file") MultipartFile file) {
        try {
            InputStream xmlStream = file.getInputStream();
            Map<String, Object> summary = xmlImporter.parseInventoryData(xmlStream);
            return ResponseEntity.ok(summary);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/cache/restore")
    public ResponseEntity<Map<String, Object>> restoreCache(
            @RequestParam("snapshot") MultipartFile snapshot) {
        try {
            InputStream dataStream = snapshot.getInputStream();
            Object restored = inventoryService.restoreCacheSnapshot(dataStream);
            return ResponseEntity.ok(Map.of(
                    "status", "restored",
                    "entries", restored.toString()
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Failed to restore cache: " + e.getMessage()));
        }
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> healthCheck() {
        return ResponseEntity.ok(Map.of("status", "operational"));
    }
}
