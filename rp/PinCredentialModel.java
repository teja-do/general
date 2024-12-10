package pwd;


	import org.keycloak.credential.CredentialModel;
	import org.keycloak.models.credential.dto.PasswordCredentialData;
	import org.keycloak.models.credential.dto.PasswordSecretData;
	import org.keycloak.util.JsonSerialization;

	import java.io.IOException;
	import java.util.List;
	import java.util.Map;

	public class PinCredentialModel extends CredentialModel {

	    public static final String TYPE = "pinpwd";
	    public static final String PASSWORD_HISTORY = "pin-history";

	    private final PasswordCredentialData credentialData;
	    private final PasswordSecretData secretData;

	    private PinCredentialModel(PasswordCredentialData credentialData, PasswordSecretData secretData) {
	        this.credentialData = credentialData;
	        this.secretData = secretData;
	    }

	    public static PinCredentialModel createFromValues(PasswordCredentialData credentialData, PasswordSecretData secretData) {
	        return new PinCredentialModel(credentialData, secretData);
	    }

	    public static PinCredentialModel createFromValues(String algorithm, byte[] salt, int hashIterations, String encodedPassword){
	        return createFromValues(algorithm, salt, hashIterations, null, encodedPassword);
	    }

	    public static PinCredentialModel createFromValues(String algorithm, byte[] salt, int hashIterations, Map<String, List<String>> additionalParameters, String encodedPassword){
	        PasswordCredentialData credentialData = new PasswordCredentialData(hashIterations, algorithm, additionalParameters);
	        PasswordSecretData secretData = new PasswordSecretData(encodedPassword, salt);

	        PinCredentialModel passwordCredentialModel = new PinCredentialModel(credentialData, secretData);

	        try {
	            passwordCredentialModel.setCredentialData(JsonSerialization.writeValueAsString(credentialData));
	            passwordCredentialModel.setSecretData(JsonSerialization.writeValueAsString(secretData));
	            passwordCredentialModel.setType(TYPE);
	            return passwordCredentialModel;
	        } catch (IOException e) {
	            throw new RuntimeException(e);
	        }
	    }

	    public static PinCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
	        try {
	            PasswordCredentialData credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(),
	                    PasswordCredentialData.class);
	            PasswordSecretData secretData = JsonSerialization.readValue(credentialModel.getSecretData(), PasswordSecretData.class);
	            PinCredentialModel passwordCredentialModel = new PinCredentialModel(credentialData, secretData);
	            passwordCredentialModel.setCreatedDate(credentialModel.getCreatedDate());
	            passwordCredentialModel.setCredentialData(credentialModel.getCredentialData());
	            passwordCredentialModel.setId(credentialModel.getId());
	            passwordCredentialModel.setSecretData(credentialModel.getSecretData());
	            passwordCredentialModel.setType(credentialModel.getType());
	            passwordCredentialModel.setUserLabel(credentialModel.getUserLabel());

	            return passwordCredentialModel;
	        } catch (IOException e) {
	            throw new RuntimeException(e);
	        }
	    }


	    public PasswordCredentialData getPasswordCredentialData() {
	        return credentialData;
	    }

	    public PasswordSecretData getPasswordSecretData() {
	        return secretData;
	    }


	}

