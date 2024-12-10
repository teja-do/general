package pwd;


import org.keycloak.credential.CredentialModel;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.provider.Provider;

/**
 * @author <a href="mailto:me@tsudot.com">Kunal Kerkar</a>
 */
public interface PinHashProvider extends Provider {
    boolean policyCheck(PasswordPolicy policy, PinCredentialModel credential);

    PinCredentialModel encodedCredential(String rawPassword, int iterations);

    /**
     * Exists due the backwards compatibility. It is recommended to use {@link #encodedCredential(String, int)}
     */
    @Deprecated
    default
    String encode(String rawPassword, int iterations) {
        return rawPassword;
    }

    boolean verify(String rawPassword, PinCredentialModel credential);

    /**
     * @deprecated Exists due the backwards compatibility. It is recommended to use {@link #policyCheck(PasswordPolicy, PinCredentialModel)}
     */
    @Deprecated
    default boolean policyCheck(PasswordPolicy policy, CredentialModel credential) {
        return policyCheck(policy, PinCredentialModel.createFromCredentialModel(credential));
    }

    /**
     * @deprecated Exists due the backwards compatibility. It is recommended to use {@link #encodedCredential(String, int)}}
     */
    @Deprecated
    default void encode(String rawPassword, int iterations, CredentialModel credential) {
        PinCredentialModel passwordCred = encodedCredential(rawPassword, iterations);

        credential.setCredentialData(passwordCred.getCredentialData());
        credential.setSecretData(passwordCred.getSecretData());
    }

    /**
     * @deprecated Exists due the backwards compatibility. It is recommended to use {@link #verify(String, PinCredentialModel)}
     */
    @Deprecated
    default boolean verify(String rawPassword, CredentialModel credential) {
        PinCredentialModel password = PinCredentialModel.createFromCredentialModel(credential);
        return verify(rawPassword, password);
    }
}
