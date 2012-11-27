package org.hisp.dhis.cas.jdbc;

import java.util.List;
import java.util.Map;
import javax.validation.constraints.NotNull;
import org.jasig.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.security.authentication.encoding.Md5PasswordEncoder;
import org.springframework.security.authentication.encoding.PasswordEncoder;

/**
 *
 * @author Saptarshi
 */
public class DhisDbAuthenticationHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler {

    @NotNull
    private String sql;
    
    @Override
    protected boolean authenticateUsernamePasswordInternal(UsernamePasswordCredentials credentials) throws AuthenticationException {
        final String username = getPrincipalNameTransformer().transform(credentials.getUsername());
        final String password = credentials.getPassword();

        try {
            final List<Map<String, Object>> rs = getJdbcTemplate().queryForList(this.sql, username);
            if (rs.size() < 1) {
                return false;
            }
            final String dbPassword = (String) rs.get(0).get("password");
            final Object salt = username.hashCode();
            PasswordEncoder passwordEncoder = new Md5PasswordEncoder();
            final String encryptedPassword = passwordEncoder.encodePassword(password, salt);

            return dbPassword.equals(encryptedPassword);
        } catch (final IncorrectResultSizeDataAccessException e) {
            // this means the username was not found. 
            return false;
        }
    }

    /**
     * @param sql The sql to set.
     */
    public void setSql(final String sql) {
        this.sql = sql;
    }

}
