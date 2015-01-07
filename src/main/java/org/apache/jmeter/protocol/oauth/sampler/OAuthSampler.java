/****************************************************************************
 * Copyright (c) 1998-2010 AOL Inc. 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ****************************************************************************/

package org.apache.jmeter.protocol.oauth.sampler;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuth.Parameter;
import net.oauth.signature.OAuthSignatureMethod;
import net.oauth.signature.RSA_SHA1;

import org.apache.jmeter.protocol.http.control.Header;
import org.apache.jmeter.protocol.http.sampler.HTTPSampleResult;
import org.apache.jmeter.protocol.http.sampler.HTTPSampler2;
import org.apache.jmeter.protocol.http.util.EncoderCache;
import org.apache.jmeter.protocol.http.util.HTTPArgument;
import org.apache.jmeter.testelement.property.PropertyIterator;
import org.apache.jorphan.logging.LoggingManager;
import org.apache.log.Logger;

/**
 * A sampler for OAuth request. It's based on HTTPSampler2 (HTTPClient).
 * This sampler adds OAuth signing to the request on the fly. Optionally,
 * it can also add OAuth parameters in Authorization header.
 * <p/>
 * <p/>It supports both HMAC-SHA1 and RSA-SHA1 algorithms. When RSA is
 * used, the private key in PEM format is needed. The file should be
 * located in the same directory as test plan if relative directory is
 * given. PLAIN is not support since the request can be done with
 * regular HTTP sampler.
 * <p/>
 * <p/>This sampler supports all HTTP sampler features except multi-part
 * file post. Currently, OAuth only supports signing of form post. This
 * may be supported in the future with OAuth body-signing extension.
 * <p/>
 * <p/>Because OAuth returns 401 on error so it behaves like HTTP auth.
 * There may be warinings in log file about unsupported HTTP auth schemes.
 * You can safely ignore these warnings.
 *
 * @author zhang
 */
public class OAuthSampler extends HTTPSampler2 {

    private static final long serialVersionUID = -4557727434430190220L;
    private static final Logger log = LoggingManager.getLoggerForClass();

    // Parameter names
    public static final String KEY = "OAuthSampler.consumer_key"; //$NON-NLS-1$
    public static final String SECRET = "OAuthSampler.consumer_secret"; //$NON-NLS-1$
    public static final String USE_AUTH_HEADER = "OAuthSampler.use_auth_header"; //$NON-NLS-1$
    public static final String SIGNATURE_METHOD = "OAuthSampler.signature_method"; //$NON-NLS-1$
    public static final String TOKEN = "OAuthSampler.oauth_token"; //$NON-NLS-1$
    public static final String TOKEN_SECRET = "OAuthSampler.token_secret"; //$NON-NLS-1$
    public static final String URL_ENCODE = "OAuthSampler.url_encode"; //$NON-NLS-1$

    // Parameter vlaues
    public static final String HMAC = "HMAC-SHA1"; //$NON-NLS-1$
    public static final String RSA = "RSA-SHA1"; //$NON-NLS-1$
    public static final String DEFAULT_METHOD = HMAC;
    // Supported methods:
    public static final String[] METHODS = {
            DEFAULT_METHOD, // i.e. HMAC-SHA1
            RSA
    };

    protected OAuthMessage message;
    protected boolean useAuthHeader;
    // When header is used, this contains remaining parameters to be sent
    protected List<Map.Entry<String, String>> nonOAuthParams = null;

    /**
     * Constructor for the OAuthSampler object. The HTTP sampler factory
     * is not used for this plugin.
     */
    public OAuthSampler() {
        super();
    }

    /**
     * Samples the URL passed in and stores the result in
     * <code>HTTPSampleResult</code>, following redirects and downloading
     * page resources as appropriate.
     * <p/>
     * When getting a redirect target, redirects are not followed and resources
     * are not downloaded. The caller will take care of this.
     *
     * @param url                  URL to sample
     * @param method               HTTP method: GET, POST,...
     * @param areFollowingRedirect whether we're getting a redirect target
     * @param frameDepth           Depth of this target in the frame structure. Used only to
     *                             prevent infinite recursion.
     * @return results of the sampling
     */
    protected HTTPSampleResult sample(URL url, String method, boolean areFollowingRedirect, int frameDepth) {

        String urlStr = url.toExternalForm();
        URL newURL = null;

        try {
            message = getOAuthMessage(url, method);
            urlStr = message.URL;

            if (useAuthHeader) {
                urlStr = OAuth.addParameters(message.URL, nonOAuthParams);
                getHeaderManager().removeHeaderNamed(HEADER_AUTHORIZATION);
                Header header = new Header();
                header.setName(HEADER_AUTHORIZATION);
                header.setValue(message.getAuthorizationHeader(""));
                getHeaderManager().add(header);
            } else {
                if(null == nonOAuthParams) {
                    nonOAuthParams = new ArrayList<Map.Entry<String, String>>();
                }
                nonOAuthParams.addAll(message.getParameters());
                urlStr = OAuth.addParameters(message.URL, nonOAuthParams);
            }

        } catch (IOException e) {
        } catch (OAuthException e) {
        } catch (URISyntaxException e) {
        }

        try {
            newURL = new URL(urlStr);
        } catch (MalformedURLException e) {
        }

        return super.sample(newURL, method, areFollowingRedirect, frameDepth);
    }

    /**
     * Create OAuth message. The message contains all HTTP arguments and
     * OAuth parameters and the signature.
     *
     * @param url
     * @param method
     * @return
     * @throws IOException
     * @throws OAuthException
     * @throws URISyntaxException
     */
    protected OAuthMessage getOAuthMessage(URL url, String method)
            throws IOException, OAuthException, URISyntaxException {

        useAuthHeader = getPropertyAsBoolean(USE_AUTH_HEADER);

        // Get OAuth accessor

        String consumerKey = getPropertyAsString(KEY);
        String signatureMethod = getPropertyAsString(SIGNATURE_METHOD);
        String secretOrKey = getPropertyAsString(SECRET);

        final OAuthConsumer consumer;
        if (RSA.equals(signatureMethod)) {
            consumer = new OAuthConsumer(null, consumerKey, null, null);
            PrivateKeyReader reader = new PrivateKeyReader(secretOrKey);
            PrivateKey key = reader.getPrivateKey();
            consumer.setProperty(RSA_SHA1.PRIVATE_KEY, key);
        } else {
            consumer = new OAuthConsumer(null, consumerKey, secretOrKey, null);
        }

        final OAuthAccessor accessor = new OAuthAccessor(consumer);
        accessor.accessToken = getDecodedProperty(TOKEN);
        accessor.tokenSecret = getDecodedProperty(TOKEN_SECRET);

        // Convert arguments to OAuth parameters, URL-decoded if already encoded.
        List<OAuth.Parameter> list =
                new ArrayList<OAuth.Parameter>(getArguments().getArgumentCount());

        PropertyIterator args = getArguments().iterator();
        while (args.hasNext()) {
            HTTPArgument arg = (HTTPArgument) args.next().getObjectValue();
            String parameterName = arg.getName();
            if (!"".equals(parameterName) && null != parameterName) {
                String parameterValue = arg.getValue();
                if (!arg.isAlwaysEncoded()) {
                    String urlContentEncoding = getContentEncoding();
                    if (urlContentEncoding == null || urlContentEncoding.length() == 0) {
                        // Use the default encoding for urls
                        urlContentEncoding = EncoderCache.URL_ARGUMENT_ENCODING;
                    }
                    parameterName = URLDecoder.decode(parameterName,
                            urlContentEncoding);
                    parameterValue = URLDecoder.decode(parameterValue,
                            urlContentEncoding);
                }

                list.add(new Parameter(parameterName, parameterValue));
            }
        }

        OAuthMessage message = new OAuthMessage(method, url.toExternalForm(), list);

        message.addParameter(OAuth.OAUTH_SIGNATURE_METHOD,
                getPropertyAsString(SIGNATURE_METHOD));

        if (accessor.accessToken != null && accessor.accessToken.length() > 0)
            message.addParameter(OAuth.OAUTH_TOKEN, accessor.accessToken);

        // Sign the message
        message.addRequiredParameters(accessor);

        if (log.isDebugEnabled()) {
            String baseString = OAuthSignatureMethod.getBaseString(message);
            log.debug("OAuth base string : '" + baseString + "'");  //$NON-NLS-1$//$NON-NLS-2$
            // It's probably ok to expose token secret
            log.debug("OAuth token secret : '" + accessor.tokenSecret + "'");  //$NON-NLS-1$//$NON-NLS-2$
        }

        if (useAuthHeader) {
            // Find the non-OAuth parameters:
            List<Map.Entry<String, String>> others = message.getParameters();
            if (others != null && !others.isEmpty()) {
                nonOAuthParams = new ArrayList<Map.Entry<String, String>>(
                        others);
                for (Iterator<Map.Entry<String, String>> p = nonOAuthParams
                        .iterator(); p.hasNext(); ) {
                    if (p.next().getKey().startsWith("oauth_")) { //$NON-NLS-1$
                        p.remove();
                    }
                }
            }
        }

        return message;
    }

    /**
     * Get property as string. If "Encode?" is not checked,
     * the property is decoded to prevent double-encoding.
     *
     * @param name Parameter name
     * @return
     */
    private String getDecodedProperty(String name) {

        String raw = getPropertyAsString(name);

        if (getPropertyAsBoolean(URL_ENCODE))
            return raw;

    	/* 
         * If the parameters doesn't need URL encode, which means
    	 * it's already encoded. It should be decoded.
    	 */

        String urlContentEncoding = getContentEncoding();
        if (urlContentEncoding == null || urlContentEncoding.length() == 0) {
            // Use the default encoding for urls
            urlContentEncoding = EncoderCache.URL_ARGUMENT_ENCODING;
        }

        try {
            return URLDecoder.decode(raw, urlContentEncoding);
        } catch (UnsupportedEncodingException e) {
            log.error("Unsupported encoding: " + e.getMessage()); //$NON-NLS-1$
            // Just return raw string
            return raw;
        }
    }
}
