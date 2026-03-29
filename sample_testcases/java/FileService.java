/**
 * UserPortal — File Upload/Download Service
 *
 * Manages file operations for user-uploaded content:
 *   - Profile image uploads
 *   - Document downloads
 *   - Attachment serving
 *
 * Files are stored under a configurable base directory on disk.
 */
package com.userportal.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class FileService {

    private static final Logger logger = Logger.getLogger(FileService.class.getName());

    @Value("${app.upload.base-dir:/var/userportal/uploads}")
    private String BASE_DIR;

    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
    private static final String[] ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".docx"};

    // -----------------------------------------------------------------------
    // TRUE POSITIVE: CWE-22 Path Traversal
    // The filename parameter (user-supplied) is passed directly to the File
    // constructor without canonicalization or prefix validation. An attacker
    // can supply "../../../etc/passwd" to read arbitrary files outside BASE_DIR.
    // -----------------------------------------------------------------------
    /**
     * Download a file by its filename. Called from the documents endpoint.
     *
     * @param filename the name of the file to retrieve
     * @return the file as a Spring Resource, or null if not found
     */
    public Resource downloadFile(String filename) {
        File file = new File(BASE_DIR, filename);
        if (!file.exists()) {
            logger.warning("Requested file not found: " + filename);
            return null;
        }
        logger.info("Serving file: " + file.getAbsolutePath());
        return new FileSystemResource(file);
    }

    /**
     * Upload a file to the storage directory.
     * Validates file size and extension before saving.
     *
     * @param file the uploaded multipart file
     * @param subDirectory optional subdirectory under BASE_DIR
     * @return the saved file's relative path
     */
    public String uploadFile(MultipartFile file, String subDirectory) throws IOException {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("Cannot upload empty file");
        }
        if (file.getSize() > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("File exceeds maximum size of 10MB");
        }

        String originalName = file.getOriginalFilename();
        if (originalName == null || !isAllowedExtension(originalName)) {
            throw new IllegalArgumentException("File type not allowed");
        }

        // Sanitize subdirectory — prevent traversal in the upload path
        String safeSub = subDirectory.replaceAll("[^a-zA-Z0-9_-]", "");
        Path targetDir = Paths.get(BASE_DIR, safeSub);
        Files.createDirectories(targetDir);

        String safeFilename = System.currentTimeMillis() + "_" + originalName.replaceAll("[^a-zA-Z0-9._-]", "");
        Path targetPath = targetDir.resolve(safeFilename);
        Files.copy(file.getInputStream(), targetPath, StandardCopyOption.REPLACE_EXISTING);

        logger.info("Uploaded file to: " + targetPath);
        return safeSub + "/" + safeFilename;
    }

    // -----------------------------------------------------------------------
    // FALSE POSITIVE #10: CWE-22 — Path traversal with proper canonicalization
    // (Contextual tier, Graph resolves)
    // SAST may flag the File(BASE_DIR, userId) construction as path traversal,
    // but the code canonicalizes the path and validates that the resulting
    // canonical path starts with the base directory. A graph analysis tracing
    // the sanitization flow would confirm this is safe.
    // -----------------------------------------------------------------------
    /**
     * Serve a user's profile image by their user ID.
     * Uses canonical path validation to prevent directory traversal.
     *
     * @param userId the user identifier used to locate the profile image
     * @return the profile image as a Resource, or null if not found
     */
    public Resource serveProfileImage(String userId) {
        try {
            File baseDir = new File(BASE_DIR, "profiles");
            File imageFile = new File(baseDir, userId + ".jpg");
            String canonicalPath = imageFile.getCanonicalPath();
            String canonicalBase = baseDir.getCanonicalPath();

            if (!canonicalPath.startsWith(canonicalBase)) {
                logger.warning("Path traversal attempt blocked for userId: " + userId);
                return null;
            }

            if (!imageFile.exists()) {
                return null;
            }
            return new FileSystemResource(imageFile);
        } catch (IOException e) {
            logger.warning("Error serving profile image: " + e.getMessage());
            return null;
        }
    }

    /**
     * Delete a file from the uploads directory.
     * Only allows deletion within the base directory (canonicalized).
     */
    public boolean deleteFile(String relativePath) throws IOException {
        Path filePath = Paths.get(BASE_DIR, relativePath).toRealPath();
        Path basePath = Paths.get(BASE_DIR).toRealPath();

        if (!filePath.startsWith(basePath)) {
            throw new SecurityException("Cannot delete files outside upload directory");
        }
        return Files.deleteIfExists(filePath);
    }

    private boolean isAllowedExtension(String filename) {
        String lower = filename.toLowerCase();
        for (String ext : ALLOWED_EXTENSIONS) {
            if (lower.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }
}
