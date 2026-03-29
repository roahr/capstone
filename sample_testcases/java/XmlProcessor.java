/**
 * UserPortal — XML Parsing Utilities
 *
 * Provides XML document parsing for:
 *   - Configuration file loading
 *   - SAML assertion processing
 *   - Data import/export in XML format
 *
 * Uses javax.xml.parsers with various security configurations.
 */
package com.userportal.util;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import org.springframework.stereotype.Component;

@Component
public class XmlProcessor {

    private static final Logger logger = Logger.getLogger(XmlProcessor.class.getName());

    // -----------------------------------------------------------------------
    // TRUE POSITIVE: CWE-611 XML External Entity (XXE) Injection
    // The DocumentBuilderFactory is created with default settings — external
    // entities and DTDs are NOT disabled. An attacker can supply XML containing
    // a DOCTYPE with an external entity reference to exfiltrate local files
    // or perform SSRF.
    // -----------------------------------------------------------------------
    /**
     * Parse an XML configuration string into a DOM Document.
     * Used for processing user-submitted configuration templates.
     *
     * @param xml raw XML string from the client
     * @return parsed Document
     * @throws Exception if parsing fails
     */
    public Document parseConfig(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputSource source = new InputSource(new StringReader(xml));
        Document doc = builder.parse(source);
        doc.getDocumentElement().normalize();
        logger.info("Parsed XML config with root element: " + doc.getDocumentElement().getTagName());
        return doc;
    }

    // -----------------------------------------------------------------------
    // FALSE POSITIVE #8: CWE-611 — XXE with external entities disabled
    // (Basic tier, SAST resolves)
    // SAST may flag the DocumentBuilderFactory usage, but the code explicitly
    // disables DOCTYPE declarations via the Apache feature flag. A basic SAST
    // rule that checks for the disallow-doctype-decl feature would clear this.
    // -----------------------------------------------------------------------
    /**
     * Parse XML securely with all external entity processing disabled.
     * Used for processing internal data feeds from trusted partners.
     *
     * @param xml raw XML string
     * @return parsed Document
     * @throws Exception if parsing fails
     */
    public Document parseSecureXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalSchema", "");

        DocumentBuilder builder = factory.newDocumentBuilder();
        InputSource source = new InputSource(new StringReader(xml));
        Document doc = builder.parse(source);
        doc.getDocumentElement().normalize();
        logger.info("Securely parsed XML with root: " + doc.getDocumentElement().getTagName());
        return doc;
    }

    /**
     * Extract all user records from an XML document.
     *
     * @param doc parsed XML document containing user elements
     * @return list of user attribute maps
     */
    public List<Map<String, String>> extractUsers(Document doc) {
        List<Map<String, String>> users = new ArrayList<>();
        NodeList nodeList = doc.getElementsByTagName("user");

        for (int i = 0; i < nodeList.getLength(); i++) {
            Element element = (Element) nodeList.item(i);
            Map<String, String> user = new HashMap<>();
            user.put("id", getTextContent(element, "id"));
            user.put("username", getTextContent(element, "username"));
            user.put("email", getTextContent(element, "email"));
            user.put("role", getTextContent(element, "role"));
            users.add(user);
        }

        logger.info("Extracted " + users.size() + " users from XML");
        return users;
    }

    /**
     * Build a secure DocumentBuilderFactory for general-purpose use.
     * Convenience method for other components.
     */
    public DocumentBuilderFactory createSecureFactory() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setNamespaceAware(true);
        return factory;
    }

    private String getTextContent(Element parent, String tagName) {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() > 0) {
            return nodes.item(0).getTextContent();
        }
        return "";
    }
}
