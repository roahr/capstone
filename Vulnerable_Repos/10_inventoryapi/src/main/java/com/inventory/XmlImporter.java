package com.inventory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class XmlImporter {

    private static final Logger logger = LoggerFactory.getLogger(XmlImporter.class);

    public Map<String, Object> parseInventoryData(InputStream xmlStream) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);

        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(xmlStream);
        document.getDocumentElement().normalize();

        NodeList itemNodes = document.getElementsByTagName("item");
        List<Map<String, String>> parsedItems = new ArrayList<>();

        for (int i = 0; i < itemNodes.getLength(); i++) {
            Element itemElement = (Element) itemNodes.item(i);
            Map<String, String> item = new HashMap<>();

            item.put("sku", getElementText(itemElement, "sku"));
            item.put("name", getElementText(itemElement, "name"));
            item.put("quantity", getElementText(itemElement, "quantity"));
            item.put("warehouse", getElementText(itemElement, "warehouse"));
            item.put("supplier", getElementText(itemElement, "supplier"));

            parsedItems.add(item);
        }

        logger.info("Parsed {} items from XML import", parsedItems.size());

        Map<String, Object> summary = new HashMap<>();
        summary.put("totalItems", parsedItems.size());
        summary.put("items", parsedItems);
        summary.put("source", document.getDocumentElement().getAttribute("source"));
        return summary;
    }

    private String getElementText(Element parent, String tagName) {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() > 0) {
            return nodes.item(0).getTextContent();
        }
        return "";
    }
}
