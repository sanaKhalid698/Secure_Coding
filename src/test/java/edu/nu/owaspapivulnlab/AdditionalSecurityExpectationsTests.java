package edu.nu.owaspapivulnlab;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Additional Security Tests
 * These tests check for secure coding and authorization fixes in the OWASP API Lab.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AdditionalSecurityExpectationsTests {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    /**
     * Helper method to login and return JWT token
     */
    String login(String user, String pw) throws Exception {
        Map<String, String> payload = Map.of(
                "username", user,
                "password", pw
        );

        String res = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(payload)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        JsonNode node = om.readTree(res);
        return node.get("token").asText();
    }

    /**
     * Test 1: Ensure protected endpoints require authentication.
     */
    @Test
    void protected_endpoints_require_authentication() throws Exception {
        mvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Test 2: Ensure only admin can delete users.
     */
    @Test
    void delete_user_requires_admin() throws Exception {
        String userToken = login("alice", "alice123"); // Normal user
        mvc.perform(delete("/api/users/1")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    /**
     * Test 3: Prevent role escalation when creating a new user.
     */
    @Test
    void create_user_does_not_allow_role_escalation() throws Exception {
        Map<String, Object> payload = Map.of(
                "username", "eve2",
                "password", "pw",
                "email", "e2@e.com",
                "role", "ADMIN",
                "isAdmin", true
        );

        mvc.perform(post("/api/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(payload)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role", anyOf(nullValue(), is("USER"))))
                .andExpect(jsonPath("$.isAdmin", anyOf(nullValue(), is(false))));
    }

    /**
     * Test 4: JWT must be valid and issuer/audience checked.
     */
    @Test
    void jwt_must_be_valid_and_aud_iss_checked() throws Exception {
        String weakToken = login("alice", "alice123");
        mvc.perform(get("/api/accounts/mine")
                        .header("Authorization", "Bearer " + weakToken))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Test 5: Users should not be able to access another user's account.
     */
    @Test
    void account_owner_only_access() throws Exception {
        String aliceToken = login("alice", "alice123");
        mvc.perform(get("/api/accounts/2/balance")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isForbidden());
    }
}
