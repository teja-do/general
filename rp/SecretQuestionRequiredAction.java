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
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.examples.authenticator.credential.PinCredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.Response;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class PinRequiredAction implements RequiredActionProvider, CredentialRegistrator {
    public static final String PROVIDER_ID = "secret_question_config";
    private static final Logger logger = Logger.getLogger(PinRequiredAction.class);

    @Override
    public void evaluateTriggers(RequiredActionContext context) {

    }

    @Override
    public String getCredentialType(KeycloakSession session, AuthenticationSessionModel AuthenticationSession) {
        return PinCredentialModel.TYPE;
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
    	logger.info(">>Context Challenge:"+context.toString());
        Response challenge = context.form().createForm("secret-question-config.ftl");
        context.challenge(challenge);
        
    }

    @Override
    public void processAction(RequiredActionContext context) {
        String answer = (context.getHttpRequest().getDecodedFormParameters().getFirst("secret_answer"));
        logger.info(">>Context Action:"+context.toString());
        PinCredentialProvider sqcp = (PinCredentialProvider) context.getSession().getProvider(CredentialProvider.class, "secret-question");
        sqcp.createCredential(context.getRealm(), context.getUser(), PinCredentialModel.createPin("What is your mom's first name?", answer));
        context.success();
    }

    @Override
    public void close() {

    }
}
