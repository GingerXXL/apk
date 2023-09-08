package org.wso2.apk.enforcer.util;

import com.google.common.cache.LoadingCache;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.opentelemetry.context.Scope;
import java.text.ParseException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.wso2.apk.enforcer.common.CacheProviderUtil;
import org.wso2.apk.enforcer.commons.dto.JWTValidationInfo;
import org.wso2.apk.enforcer.commons.exception.APISecurityException;
import org.wso2.apk.enforcer.commons.exception.EnforcerException;
import org.wso2.apk.enforcer.constants.APIConstants;
import org.wso2.apk.enforcer.constants.APISecurityConstants;
import org.wso2.apk.enforcer.security.jwt.CachedJWTInfo;
import org.wso2.apk.enforcer.security.jwt.validator.JWTValidator;
import org.wso2.apk.enforcer.security.jwt.validator.RevokedJWTDataHolder;
import org.wso2.apk.enforcer.subscription.SubscriptionDataStoreImpl;
import org.wso2.apk.enforcer.tracing.TracingConstants;
import org.wso2.apk.enforcer.tracing.TracingSpan;
import org.wso2.apk.enforcer.tracing.TracingTracer;
import org.wso2.apk.enforcer.tracing.Utils;

public class CachedJWTUtils {
    private static final Logger log = LogManager.getLogger(CachedJWTUtils.class);
    

    /**
     * Get the internal representation of the JWT.
     *
     * @param accessToken the raw access token
     * @return the internal representation of the JWT
     * @throws ParseException if an error occurs when decoding the JWT
     */
    public static CachedJWTInfo validateJwt(String accessToken, String organization, boolean isGatewayTokenCacheEnabled) throws APISecurityException {

        // TODO(amali) handle isGatewayTokenCacheEnabled
        CachedJWTInfo cachedJWTInfo;
        LoadingCache gatewaySignedJWTParseCache = CacheProviderUtil.getOrganizationCache(organization).getGatewaySignedJWTParseCache();
        if (gatewaySignedJWTParseCache != null) {
            Object cachedEntry = gatewaySignedJWTParseCache.getIfPresent(accessToken);
            if (cachedEntry != null) {
                cachedJWTInfo = (CachedJWTInfo) cachedEntry;
//                return cachedJWTInfo;
            }
        }
        
        // -------------
        
        TracingTracer tracer;
        Scope decodeTokenHeaderSpanScope = null;
        TracingSpan decodeTokenHeaderSpan = null;
        SignedJWT signedJWT;
        try {
            if (Utils.tracingEnabled()) {
                tracer = Utils.getGlobalTracer();
                decodeTokenHeaderSpan = Utils.startSpan(TracingConstants.DECODE_TOKEN_HEADER_SPAN, tracer);
                decodeTokenHeaderSpanScope = decodeTokenHeaderSpan.getSpan().makeCurrent();
                Utils.setTag(decodeTokenHeaderSpan, APIConstants.LOG_TRACE_ID,
                        ThreadContext.get(APIConstants.LOG_TRACE_ID));
            }
            signedJWT = SignedJWT.parse(accessToken);
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
            cachedJWTInfo = new CachedJWTInfo(signedJWT, jwtClaimsSet);
            // TODO(amali) set this after only validating the whole token
            gatewaySignedJWTParseCache.put(accessToken, cachedJWTInfo);

        } catch (ParseException | IllegalArgumentException e) {
            log.error("Failed to decode the token header. {}", e.getMessage());
            throw new APISecurityException(APIConstants.StatusCodes.UNAUTHENTICATED.getCode(),
                    APISecurityConstants.API_AUTH_INVALID_CREDENTIALS, "Not a JWT token. Failed to decode the " +
                    "token header", e);
        } finally {
            if (Utils.tracingEnabled()) {
                decodeTokenHeaderSpanScope.close();
                Utils.finishSpan(decodeTokenHeaderSpan);
            }
        }

        String jwtTokenIdentifier = getJWTTokenIdentifier(cachedJWTInfo);
        String jwtHeader = cachedJWTInfo.getSignedJWT().getHeader().toString();
        if (StringUtils.isNotEmpty(jwtTokenIdentifier)) {
            if (RevokedJWTDataHolder.isJWTTokenSignatureExistsInRevokedMap(jwtTokenIdentifier)) {
                log.debug("Token retrieved from the revoked jwt token map. Token: " + FilterUtils.getMaskedToken(jwtHeader));
                throw new APISecurityException(APIConstants.StatusCodes.UNAUTHENTICATED.getCode(),
                        APISecurityConstants.API_AUTH_INVALID_CREDENTIALS, "Invalid JWT token");
            }
        }
        return cachedJWTInfo;
    }

    private static String getJWTTokenIdentifier(CachedJWTInfo cachedJWTInfo) {
        JWTClaimsSet jwtClaimsSet = cachedJWTInfo.getJwtClaimsSet();
        String jwtid = jwtClaimsSet.getJWTID();
        if (StringUtils.isNotEmpty(jwtid)) {
            return jwtid;
        }
        return cachedJWTInfo.getSignedJWT().getSignature().toString();
    }


    /**
     * 
     * @param cachedJWTInfo contains decoded JWT
     * @param tokenIdentifier this could be jti or signature see method getJWTTokenIdentifier
     * @param organization
     * @return
     * @throws APISecurityException
     */
    private JWTValidationInfo getJwtValidationInfo(CachedJWTInfo cachedJWTInfo, String tokenIdentifier, String organization) throws APISecurityException {

        String jwtHeader = cachedJWTInfo.getSignedJWT().getHeader().toString();
        JWTValidationInfo jwtValidationInfo = null;
        // todo(amali) check if this is needed
//        if (isGatewayTokenCacheEnabled && !CachedJWTInfo.ValidationStatus.NOT_VALIDATED.equals(cachedJWTInfo.getValidationStatus())) {
//            Object cacheToken =
//                    CacheProviderUtil.getOrganizationCache(organization).getGatewayTokenCache().getIfPresent(tokenIdentifier);
//            if (cacheToken != null && (Boolean) cacheToken && CachedJWTInfo.ValidationStatus.VALID.equals(cachedJWTInfo.getValidationStatus())) {
//                if (CacheProviderUtil.getOrganizationCache(organization).getGatewayKeyCache().getIfPresent(tokenIdentifier) != null) {
//                    JWTValidationInfo tempJWTValidationInfo =
//                            (JWTValidationInfo) CacheProviderUtil.getOrganizationCache(organization).getGatewayKeyCache().getIfPresent(tokenIdentifier);
//                    checkTokenExpiration(tokenIdentifier, tempJWTValidationInfo, organization);
//                    jwtValidationInfo = tempJWTValidationInfo;
//                }
//            } else if (CachedJWTInfo.ValidationStatus.INVALID.equals(cachedJWTInfo.getValidationStatus())
//                    || CacheProviderUtil.getOrganizationCache(organization).getInvalidTokenCache().getIfPresent(tokenIdentifier) != null) {
//                if (log.isDebugEnabled()) {
//                    log.debug("Token retrieved from the invalid token cache. Token: " + FilterUtils.getMaskedToken(jwtHeader));
//                }
//                log.debug("Invalid JWT token. " + FilterUtils.getMaskedToken(jwtHeader));
//                throw new APISecurityException(APIConstants.StatusCodes.UNAUTHENTICATED.getCode(),
//                        APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
//                        APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE);
//            }
//        }

        try {
            jwtValidationInfo = validateJWTToken(cachedJWTInfo, organization);
            cachedJWTInfo.setValidationStatus(jwtValidationInfo.isValid() ? CachedJWTInfo.ValidationStatus.VALID
                    : CachedJWTInfo.ValidationStatus.INVALID);
//            if (isGatewayTokenCacheEnabled) {
//                // Add token to tenant token cache
//                if (jwtValidationInfo.isValid()) {
//                    CacheProviderUtil.getOrganizationCache(organization).getGatewayTokenCache().put(tokenIdentifier, true);
//                } else {
//                    CacheProviderUtil.getOrganizationCache(organization).getInvalidTokenCache().put(tokenIdentifier, true);
//                }
//                CacheProviderUtil.getOrganizationCache(organization).getGatewayKeyCache().put(tokenIdentifier,
//                        jwtValidationInfo);
//
//            }
            return jwtValidationInfo;
        } catch (EnforcerException e) {
            log.error("JWT Validation failed", e);
            throw new APISecurityException(APIConstants.StatusCodes.UNAUTHENTICATED.getCode(),
                    APISecurityConstants.API_AUTH_GENERAL_ERROR,
                    APISecurityConstants.API_AUTH_GENERAL_ERROR_MESSAGE);
        }
    }

    public static JWTValidationInfo validateJWTToken(CachedJWTInfo cachedJWTInfo, String organization) throws EnforcerException {

        JWTValidationInfo jwtValidationInfo = new JWTValidationInfo();
        String issuer = cachedJWTInfo.getJwtClaimsSet().getIssuer();
        JWTValidator jwtValidator = SubscriptionDataStoreImpl.getInstance().getJWTValidatorByIssuer(issuer,
                organization);
        if (jwtValidator != null) {
            return jwtValidator.validateToken(cachedJWTInfo);
        }
        jwtValidationInfo.setValid(false);
        jwtValidationInfo.setValidationCode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
        log.info("No matching issuer found for the token with issuer : " + issuer);
        return jwtValidationInfo;

    }
}
