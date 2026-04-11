package com.reportgen;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

@Service
public class LdapLookup {

    private static final Logger logger = LoggerFactory.getLogger(LdapLookup.class);

    @Value("${ldap.url:ldap://localhost:389}")
    private String ldapUrl;

    @Value("${ldap.base:dc=corp,dc=local}")
    private String baseDn;

    public Map<String, String> getUserDetails(String username) throws Exception {
        logger.info("Looking up user details for: {}", username);

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl + "/" + baseDn);

        DirContext ctx = new InitialDirContext(env);

        String filter = "(uid=" + username + ")";
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[]{"cn", "mail", "department", "title"});

        NamingEnumeration<SearchResult> results = ctx.search("", filter, controls);

        Map<String, String> userDetails = new HashMap<>();
        if (results.hasMore()) {
            SearchResult result = results.next();
            Attributes attrs = result.getAttributes();

            userDetails.put("displayName", getAttributeValue(attrs, "cn"));
            userDetails.put("email", getAttributeValue(attrs, "mail"));
            userDetails.put("department", getAttributeValue(attrs, "department"));
            userDetails.put("title", getAttributeValue(attrs, "title"));
        }

        ctx.close();
        logger.info("Retrieved {} attributes for user {}", userDetails.size(), username);
        return userDetails;
    }

    private String getAttributeValue(Attributes attrs, String name) throws Exception {
        Attribute attr = attrs.get(name);
        return attr != null ? attr.get().toString() : "";
    }
}
