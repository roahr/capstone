/**
 * UserPortal — LDAP Directory Operations
 *
 * Handles user lookups and authentication against the corporate
 * LDAP directory (Active Directory / OpenLDAP):
 *   - User search by various attributes
 *   - Group membership queries
 *   - Employee record lookups
 *
 * Uses javax.naming (JNDI) for LDAP operations.
 */
package com.userportal.service;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class DirectoryService {

    private static final Logger logger = Logger.getLogger(DirectoryService.class.getName());

    @Value("${ldap.url:ldap://ldap.corp.internal:389}")
    private String ldapUrl;

    @Value("${ldap.base-dn:dc=corp,dc=internal}")
    private String baseDn;

    @Value("${ldap.bind-dn:cn=svc-userportal,ou=services,dc=corp,dc=internal}")
    private String bindDn;

    @Value("${ldap.bind-password:}")
    private String bindPassword;

    /**
     * Create an authenticated LDAP context for directory operations.
     */
    private DirContext createContext() throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl + "/" + baseDn);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, bindDn);
        env.put(Context.SECURITY_CREDENTIALS, bindPassword);
        return new InitialDirContext(env);
    }

    // -----------------------------------------------------------------------
    // TRUE POSITIVE: CWE-90 LDAP Injection
    // The username parameter is concatenated directly into the LDAP search
    // filter without any escaping. An attacker can inject LDAP filter syntax
    // (e.g., "*)(uid=*))(|(uid=*") to bypass authentication or enumerate
    // all directory entries.
    // -----------------------------------------------------------------------
    /**
     * Look up a user in the LDAP directory by their username.
     *
     * @param username the login name to search for
     * @return list of matching attribute maps
     * @throws NamingException if the LDAP query fails
     */
    public List<SearchResult> findUser(String username) throws NamingException {
        DirContext ctx = createContext();
        try {
            String filter = "(uid=" + username + ")";
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{"uid", "cn", "mail", "employeeNumber"});

            logger.info("LDAP search with filter: " + filter);
            NamingEnumeration<SearchResult> results = ctx.search("ou=people", filter, controls);

            List<SearchResult> users = new ArrayList<>();
            while (results.hasMore()) {
                users.add(results.next());
            }
            logger.info("Found " + users.size() + " LDAP entries for username query");
            return users;
        } finally {
            ctx.close();
        }
    }

    // -----------------------------------------------------------------------
    // FALSE POSITIVE #12: CWE-90 — LDAP filter with validated input
    // (Adversarial tier, LLM resolves)
    // SAST will flag the string concatenation in the LDAP filter, but the
    // empId parameter is validated against a strict regex pattern [0-9]{6}
    // BEFORE it reaches the filter construction. Since empId can only contain
    // exactly 6 digits, no LDAP metacharacters can be injected. Recognising
    // this requires understanding the regex constraint on the value space.
    // -----------------------------------------------------------------------
    /**
     * Find a user by their employee ID (6-digit numeric identifier).
     * Employee IDs are validated to be exactly 6 digits before lookup.
     *
     * @param empId the 6-digit employee identifier
     * @return list of matching search results
     * @throws NamingException if the LDAP query fails
     * @throws IllegalArgumentException if empId format is invalid
     */
    public List<SearchResult> findUserByEmployeeId(String empId) throws NamingException {
        if (empId == null || !empId.matches("[0-9]{6}")) {
            throw new IllegalArgumentException(
                    "Employee ID must be exactly 6 digits, got: " + empId);
        }

        DirContext ctx = createContext();
        try {
            String filter = "(employeeNumber=" + empId + ")";
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{"uid", "cn", "mail", "employeeNumber", "department"});

            logger.info("LDAP search by employee ID: " + empId);
            NamingEnumeration<SearchResult> results = ctx.search("ou=people", filter, controls);

            List<SearchResult> users = new ArrayList<>();
            while (results.hasMore()) {
                users.add(results.next());
            }
            return users;
        } finally {
            ctx.close();
        }
    }

    /**
     * Retrieve all members of an LDAP group.
     * Group name is from internal config, not user input.
     *
     * @param groupName the LDAP group CN
     * @return list of member DNs
     */
    public List<String> getGroupMembers(String groupName) throws NamingException {
        DirContext ctx = createContext();
        try {
            // Group names come from application config, safe to use directly
            String filter = "(cn=" + groupName + ")";
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{"member"});

            NamingEnumeration<SearchResult> results = ctx.search("ou=groups", filter, controls);
            List<String> members = new ArrayList<>();

            if (results.hasMore()) {
                Attributes attrs = results.next().getAttributes();
                if (attrs.get("member") != null) {
                    NamingEnumeration<?> memberEnum = attrs.get("member").getAll();
                    while (memberEnum.hasMore()) {
                        members.add(memberEnum.next().toString());
                    }
                }
            }

            logger.info("Group " + groupName + " has " + members.size() + " members");
            return members;
        } finally {
            ctx.close();
        }
    }
}
