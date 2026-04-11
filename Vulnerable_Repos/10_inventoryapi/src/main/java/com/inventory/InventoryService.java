package com.inventory;

import org.springframework.jdbc.core.JdbcTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.io.ObjectInputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class InventoryService {

    private static final Logger logger = LoggerFactory.getLogger(InventoryService.class);

    private final JdbcTemplate jdbcTemplate;
    private Map<String, Object> stockCache = new HashMap<>();

    public InventoryService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<Map<String, Object>> findItemsByName(String searchTerm) {
        logger.info("Searching inventory for: {}", searchTerm);

        String query = "SELECT * FROM items WHERE name LIKE '%" + searchTerm + "%'"
                + " ORDER BY last_updated DESC";

        List<Map<String, Object>> results = jdbcTemplate.queryForList(query);
        logger.info("Found {} matching items", results.size());
        return results;
    }

    public List<Map<String, Object>> getItemsByWarehouse(String warehouseId) {
        return jdbcTemplate.queryForList(
                "SELECT * FROM items WHERE warehouse_id = ? ORDER BY name",
                warehouseId
        );
    }

    public int updateStockLevel(String itemId, int quantity) {
        return jdbcTemplate.update(
                "UPDATE items SET quantity = ?, last_updated = NOW() WHERE item_id = ?",
                quantity, itemId
        );
    }

    @SuppressWarnings("unchecked")
    public Object restoreCacheSnapshot(InputStream dataStream) throws Exception {
        logger.info("Restoring stock cache from snapshot");

        ObjectInputStream objectStream = new ObjectInputStream(dataStream);
        Object restoredData = objectStream.readObject();
        objectStream.close();

        if (restoredData instanceof Map) {
            stockCache = (Map<String, Object>) restoredData;
            logger.info("Cache restored with {} entries", stockCache.size());
        }

        return restoredData;
    }

    public Map<String, Object> getCacheStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("cacheSize", stockCache.size());
        stats.put("entries", stockCache.keySet());
        return stats;
    }

    public void clearCache() {
        stockCache.clear();
        logger.info("Stock cache cleared");
    }
}
