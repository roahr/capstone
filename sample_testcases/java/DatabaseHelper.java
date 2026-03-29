/**
 * UserPortal — Database Query Utilities
 *
 * Provides low-level database access for the user management application:
 *   - User CRUD operations
 *   - Search queries
 *   - Reporting queries
 *
 * Uses JDBC with a connection pool for MySQL/PostgreSQL backends.
 */
package com.userportal.service;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.userportal.model.User;

@Repository
public class DatabaseHelper {

    private static final Logger logger = Logger.getLogger(DatabaseHelper.class.getName());

    @Autowired
    private DataSource dataSource;

    /**
     * Obtain a connection from the pool.
     */
    private Connection getConnection() throws SQLException {
        return dataSource.getConnection();
    }

    // -----------------------------------------------------------------------
    // TRUE POSITIVE: CWE-89 SQL Injection
    // The name parameter (user-supplied) is concatenated directly into the
    // SQL query string. An attacker can inject arbitrary SQL via the name
    // parameter (e.g., "' OR '1'='1' --") to dump the entire users table
    // or perform other unauthorized operations.
    // -----------------------------------------------------------------------
    /**
     * Search for users whose name matches the given string.
     * Used by the admin search panel.
     *
     * @param name search term from the user
     * @return list of matching User objects
     */
    public List<User> findUsersByName(String name) {
        List<User> users = new ArrayList<>();
        try (Connection conn = getConnection()) {
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(
                    "SELECT * FROM users WHERE name = '" + name + "'");
            while (rs.next()) {
                users.add(mapRowToUser(rs));
            }
            logger.info("Found " + users.size() + " users matching name: " + name);
        } catch (SQLException e) {
            logger.severe("Query failed in findUsersByName: " + e.getMessage());
        }
        return users;
    }

    // -----------------------------------------------------------------------
    // FALSE POSITIVE #7: CWE-89 — Parameterized query with PreparedStatement
    // (Basic tier, SAST resolves)
    // SAST may flag this method due to the SQL string and JDBC usage, but the
    // query uses a PreparedStatement with a `?` placeholder. The id parameter
    // is bound via setInt(), making SQL injection impossible. A basic SAST
    // rule recognising PreparedStatement parameter binding would clear this.
    // -----------------------------------------------------------------------
    /**
     * Fetch a single user by their database ID.
     * Uses parameterized query for safe execution.
     *
     * @param id the user's primary key
     * @return the User, or null if not found
     */
    public User getUserById(int id) {
        try (Connection conn = getConnection()) {
            PreparedStatement pstmt = conn.prepareStatement(
                    "SELECT * FROM users WHERE id = ?");
            pstmt.setInt(1, id);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return mapRowToUser(rs);
            }
        } catch (SQLException e) {
            logger.severe("Query failed in getUserById: " + e.getMessage());
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // FALSE POSITIVE #11: CWE-89 — String concat with enum-constrained value
    // (Adversarial tier, LLM resolves)
    // SAST will flag the string concatenation in the SQL query, but the
    // status parameter is validated against a fixed set of enum values
    // ("active", "inactive", "pending") before reaching this method. The
    // caller ensures only these three values are ever passed. Since the
    // value space is fully constrained to safe string literals, no injection
    // is possible. Recognising this requires understanding the enum constraint
    // across the call boundary.
    // -----------------------------------------------------------------------
    /**
     * Get all users with a specific account status.
     * The status parameter is guaranteed by the caller (UserService) to be one
     * of the AccountStatus enum values: "active", "inactive", or "pending".
     *
     * @param status one of "active", "inactive", "pending" (from AccountStatus enum)
     * @return list of users with the given status
     */
    public List<User> getActiveUsers(String status) {
        // Status comes from AccountStatus.name() — only "active", "inactive", "pending"
        List<User> users = new ArrayList<>();
        try (Connection conn = getConnection()) {
            Statement stmt = conn.createStatement();
            String sql = "SELECT * FROM users WHERE status = '" + status + "' ORDER BY created_at DESC";
            ResultSet rs = stmt.executeQuery(sql);
            while (rs.next()) {
                users.add(mapRowToUser(rs));
            }
            logger.info("Found " + users.size() + " users with status: " + status);
        } catch (SQLException e) {
            logger.severe("Query failed in getActiveUsers: " + e.getMessage());
        }
        return users;
    }

    /**
     * Count total users in the system. Used for dashboard metrics.
     */
    public int countUsers() {
        try (Connection conn = getConnection()) {
            PreparedStatement pstmt = conn.prepareStatement("SELECT COUNT(*) FROM users");
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            logger.severe("Count query failed: " + e.getMessage());
        }
        return 0;
    }

    /**
     * Insert a new user record. Returns the generated ID.
     */
    public int createUser(User user) throws SQLException {
        String sql = "INSERT INTO users (username, name, email, status, created_at) VALUES (?, ?, ?, ?, NOW())";
        try (Connection conn = getConnection()) {
            PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setString(1, user.getUsername());
            pstmt.setString(2, user.getName());
            pstmt.setString(3, user.getEmail());
            pstmt.setString(4, user.getStatus());
            pstmt.executeUpdate();

            ResultSet keys = pstmt.getGeneratedKeys();
            if (keys.next()) {
                int newId = keys.getInt(1);
                logger.info("Created user with ID: " + newId);
                return newId;
            }
        }
        throw new SQLException("Failed to create user, no ID generated");
    }

    /**
     * Map a ResultSet row to a User domain object.
     */
    private User mapRowToUser(ResultSet rs) throws SQLException {
        User user = new User();
        user.setId(rs.getInt("id"));
        user.setUsername(rs.getString("username"));
        user.setName(rs.getString("name"));
        user.setEmail(rs.getString("email"));
        user.setStatus(rs.getString("status"));
        return user;
    }
}
