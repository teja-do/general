/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pwd;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelException;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class PinCredentialProvider implements CredentialProvider<PinCredentialModel>, CredentialInputUpdater,
        CredentialInputValidator {

    private static final Logger logger = Logger.getLogger(PinCredentialProvider.class);

    protected final KeycloakSession session;

    public PinCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    public PinCredentialModel getPassword(RealmModel realm, UserModel user) {
        List<CredentialModel> passwords = user.credentialManager().getStoredCredentialsByTypeStream(getType()).collect(Collectors.toList());
        if (passwords.isEmpty()) return null;
        return PinCredentialModel.createFromCredentialModel(passwords.get(0));
    }

    public boolean createCredential(RealmModel realm, UserModel user, String password) {
        PasswordPolicy policy = realm.getPasswordPolicy();

        PolicyError error = session.getProvider(PasswordPolicyManagerProvider.class).validate(realm, user, password);
        if (error != null) throw new ModelException(error.getMessage(), error.getParameters());

        PinHashProvider hash = getHashProvider(policy);
        if (hash == null) {
            return false;
        }
        try {
            PinCredentialModel credentialModel = hash.encodedCredential(password, policy.getHashIterations());
            credentialModel.setCreatedDate(Time.currentTimeMillis());
            createCredential(realm, user, credentialModel);
        } catch (Throwable t) {
            throw new ModelException(t.getMessage(), t);
        }
        return true;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, PinCredentialModel credentialModel) {

        PasswordPolicy policy = realm.getPasswordPolicy();
        int expiredPasswordsPolicyValue = policy.getExpiredPasswords();

        // 1) create new or reset existing password
        CredentialModel createdCredential;
        CredentialModel oldPassword = getPassword(realm, user);
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }
        if (oldPassword == null) { // no password exists --> create new
            createdCredential = user.credentialManager().createStoredCredential(credentialModel);
        } else { // password exists --> update existing
            credentialModel.setId(oldPassword.getId());
            user.credentialManager().updateStoredCredential(credentialModel);
            createdCredential = credentialModel;

            // 2) add a password history item based on the old password
            if (expiredPasswordsPolicyValue > 1) {
                oldPassword.setId(null);
                oldPassword.setType(PinCredentialModel.PASSWORD_HISTORY);
                user.credentialManager().createStoredCredential(oldPassword);
            }
        }
        
        // 3) remove old password history items
        final int passwordHistoryListMaxSize = Math.max(0, expiredPasswordsPolicyValue - 1);
        user.credentialManager().getStoredCredentialsByTypeStream(PinCredentialModel.PASSWORD_HISTORY)
                .sorted(CredentialModel.comparingByStartDateDesc())
                .skip(passwordHistoryListMaxSize)
                .collect(Collectors.toList())
                .forEach(p -> user.credentialManager().removeStoredCredentialById(p.getId()));

        return createdCredential;
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return user.credentialManager().removeStoredCredentialById(credentialId);
    }

    @Override
    public PinCredentialModel getCredentialFromModel(CredentialModel model) {
        return PinCredentialModel.createFromCredentialModel(model);
    }


    protected PinHashProvider getHashProvider(PasswordPolicy policy) {
        if (policy != null && policy.getHashAlgorithm() != null) {
            PinHashProvider provider = session.getProvider(PinHashProvider.class, policy.getHashAlgorithm());
            if (provider != null) {
                return provider;
            } else {
                logger.warnv("Realm PasswordPolicy PinHashProvider {0} not found", policy.getHashAlgorithm());
            }
        }

        return session.getProvider(PinHashProvider.class);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return credentialType.equals(getType());
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        return createCredential(realm, user, input.getChallengeResponse());
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {

    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realm, UserModel user) {
        return Stream.empty();
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return getPassword(realm, user) != null;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!(input instanceof UserCredentialModel)) {
            logger.debug("Expected instance of UserCredentialModel for CredentialInput");
            return false;

        }
        if (input.getChallengeResponse() == null) {
            logger.debugv("Input password was null for user {0} ", user.getUsername());
            return false;
        }
        PinCredentialModel password = getPassword(realm, user);
        if (password == null) {
            logger.debugv("No password stored for user {0} ", user.getUsername());
            return false;
        }
        PinHashProvider hash = session.getProvider(PinHashProvider.class, password.getPasswordCredentialData().getAlgorithm());
        if (hash == null) {
            logger.debugv("PinHashProvider {0} not found for user {1} ", password.getPasswordCredentialData().getAlgorithm(), user.getUsername());
            return false;
        }
        try {
            if (!hash.verify(input.getChallengeResponse(), password)) {
                logger.debugv("Failed password validation for user {0} ", user.getUsername());
                return false;
            }

            rehashPasswordIfRequired(session, realm, user, input, password);
        } catch (Throwable t) {
            logger.warn("Error when validating user password", t);
            return false;
        }

        return true;
    }

    private void rehashPasswordIfRequired(KeycloakSession session, RealmModel realm, UserModel user, CredentialInput input, PinCredentialModel pin) {
        PasswordPolicy passwordPolicy = realm.getPasswordPolicy();
        PinHashProvider provider;
        if (passwordPolicy != null && passwordPolicy.getHashAlgorithm() != null) {
            provider = session.getProvider(PinHashProvider.class, passwordPolicy.getHashAlgorithm());
        } else {
            provider = session.getProvider(PinHashProvider.class);
        }

        if (!provider.policyCheck(passwordPolicy, pin)) {
            int iterations = passwordPolicy != null ? passwordPolicy.getHashIterations() : -1;

            PinCredentialModel newPin = provider.encodedCredential(input.getChallengeResponse(), iterations);
            newPin.setId(pin.getId());
            newPin.setCreatedDate(pin.getCreatedDate());
            newPin.setUserLabel(pin.getUserLabel());
            user.credentialManager().updateStoredCredential(newPin);
        }
    }

    @Override
    public String getType() {
        return PinCredentialModel.TYPE;
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        CredentialTypeMetadata.CredentialTypeMetadataBuilder metadataBuilder = CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.BASIC_AUTHENTICATION)
                .displayName("password-display-name")
                .helpText("password-help-text")
                .iconCssClass("kcAuthenticatorPasswordClass");

        // Check if we are creating or updating password
        UserModel user = metadataContext.getUser();
        if (user != null && user.credentialManager().isConfiguredFor(getType())) {
            metadataBuilder.updateAction(UserModel.RequiredAction.UPDATE_PASSWORD.toString());
        } else {
            metadataBuilder.createAction(UserModel.RequiredAction.UPDATE_PASSWORD.toString());
        }

        return metadataBuilder
                .removeable(false)
                .build(session);
    }

	
}
