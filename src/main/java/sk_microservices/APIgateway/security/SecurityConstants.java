package sk_microservices.APIgateway.security;

public final class SecurityConstants {

    public static final String SECRET = "mySecretKey";

    public static final long TOKEN_EXPIRATION_TIME = 86400000;
    public static final String TOKEN_PREFIX = "Basic ";
    public static final String HEADER_STRING = "Authorization";

    public static final String AUTH_LOGIN_PATH = "/rest-user-service/auth/login";
    public static final String AUTH_SIGNIN_PATH = "/rest-user-service/auth/signin";
    public static final String AUTH_REGISTER_PATH = "/rest-user-service/auth/login";
    public static final String LOGIN_PATH = "/rest-user-service/login";

}
