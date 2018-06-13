package com.willblaschko.android.alexa;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import com.amazon.identity.auth.device.AuthError;
import com.amazon.identity.auth.device.authorization.api.AmazonAuthorizationManager;
import com.google.gson.Gson;
import com.willblaschko.android.alexa.connection.ClientUtil;
import com.willblaschko.android.alexa.utility.Util;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * A utility class designed to request, receive, store, and renew Amazon authentication tokens using a Volley interface and the Amazon auth API
 *
 * Some more details here: https://developer.amazon.com/public/solutions/alexa/alexa-voice-service/docs/authorizing-your-alexa-enabled-product-from-a-website
 */
public class TokenManager {

    private final static String TAG = "TokenManager";

    private static String REFRESH_TOKEN;
    private static String ACCESS_TOKEN;

    private final static String ARG_GRANT_TYPE = "grant_type";
    private final static String ARG_CODE = "code";
    private final static String ARG_REDIRECT_URI = "redirect_uri";
    private final static String ARG_CLIENT_ID = "client_id";
    private final static String ARG_CODE_VERIFIER = "code_verifier";
    private final static String ARG_REFRESH_TOKEN = "refresh_token";


    public final static String PREF_ACCESS_TOKEN = "access_token_042017";
    public final static String PREF_REFRESH_TOKEN = "refresh_token_042017";
    public final static String PREF_TOKEN_EXPIRES = "token_expires_042017";

    /**
     * Get an access token from the Amazon servers for the current user
     * @param context local/application level context
     * @param authCode the authorization code supplied by the Authorization Manager
     * @param codeVerifier a randomly generated verifier, must be the same every time
     * @param authorizationManager the AuthorizationManager class calling this function
     * @param callback the callback for state changes
     */
    public static void getAccessToken(final Context context, @NotNull String authCode, @NotNull String codeVerifier, AmazonAuthorizationManager authorizationManager, @Nullable final TokenResponseCallback callback){
        //this url shouldn't be hardcoded, but it is, it's the Amazon auth access token endpoint
        String url = "https://api.amazon.com/auth/O2/token";
        //set up our arguments for the api call, these will be the call headers
        FormBody.Builder builder = new FormBody.Builder()
                .add(ARG_GRANT_TYPE, "authorization_code")
                .add(ARG_CODE, authCode);
        /*try {
            Log.d(TAG, "getAccessToken: ARG_REDIRECT_URI-"+authorizationManager.getRedirectUri()+"-ARG_CLIENT_ID-"+authorizationManager.getClientId()+"-authCode-"+authCode);
            builder.add(ARG_CLIENT_ID,authorizationManager.getClientId());
            builder.add(ARG_REDIRECT_URI,authorizationManager.getRedirectUri());
        } catch (AuthError authError) {
            authError.printStackTrace();
        }*/
        builder.add(ARG_REDIRECT_URI, "amzn://com.willblaschko.android.alexavoicelibrary");
        builder.add(ARG_CLIENT_ID, "amzn1.application-oa2-client.37f709d55e354ea6b4defad65b077f50");
        builder.add(ARG_CODE_VERIFIER, codeVerifier);

        OkHttpClient client = ClientUtil.getTLS12OkHttpClient();

        Request request = new Request.Builder()
                .url(url)
                .post(builder.build())
                .build();

        final Handler handler = new Handler(Looper.getMainLooper());


        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, final IOException e) {
                e.printStackTrace();
                if(callback != null){
                    //bubble up error
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            callback.onFailure(e);
                        }
                    });
                }
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                String s = response.body().string();
                Log.d(TAG, "onResponse: "+s);
                if(BuildConfig.DEBUG) {
                    Log.i(TAG, s);
                }
                final TokenResponse tokenResponse = new Gson().fromJson(s, TokenResponse.class);
                //save our tokens to local shared preferences
                firstsaveTokens(context, tokenResponse);

                if(callback != null){
                    //bubble up success
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            Log.d(TAG, "run: getAccessToken");
                            callback.onSuccess(tokenResponse);
                        }
                    });
                }
            }
        });

    }

    /**
     * Check if we have a pre-existing access token, and whether that token is expired. If it is not, return that token, otherwise get a refresh token and then
     * use that to get a new token.
     * @param authorizationManager our AuthManager
     * @param context local/application context
     * @param callback the TokenCallback where we return our tokens when successful
     */
    public static void getAccessToken(@NotNull AmazonAuthorizationManager authorizationManager, @NotNull Context context, @NotNull TokenCallback callback) {
        SharedPreferences preferences = Util.getPreferences(context.getApplicationContext());
        //if we have an access token
        if(preferences.contains(PREF_ACCESS_TOKEN)){

            if(preferences.getLong(PREF_TOKEN_EXPIRES, 0) > System.currentTimeMillis()){
                //if it's not expired, return the existing token
                callback.onSuccess(preferences.getString(PREF_ACCESS_TOKEN, null));
                return;
            }else{
                //if it is expired but we have a refresh token, get a new token
                if(preferences.contains(PREF_REFRESH_TOKEN)){
                    getRefreshToken(authorizationManager, context, callback, preferences.getString(PREF_REFRESH_TOKEN, ""));
                    return;
                }
            }
        }

        //uh oh, the user isn't logged in, we have an IllegalStateException going on!
        callback.onFailure(new IllegalStateException("User is not logged in and no refresh token found."));
    }

    /**
     * Get a new refresh token from the Amazon server to replace the expired access token that we currently have
     * @param authorizationManager
     * @param context
     * @param callback
     * @param refreshToken the refresh token we have stored in local cache (sharedPreferences)
     */
    private static void getRefreshToken(@NotNull AmazonAuthorizationManager authorizationManager, @NotNull final Context context, @NotNull final TokenCallback callback, String refreshToken){
        //this url shouldn't be hardcoded, but it is, it's the Amazon auth access token endpoint
        String url = "https://api.amazon.com/auth/O2/token";


        //set up our arguments for the api call, these will be the call headers
        FormBody.Builder builder = new FormBody.Builder()
                .add(ARG_GRANT_TYPE, "refresh_token")
                .add(ARG_REFRESH_TOKEN, refreshToken);
            //builder.add(ARG_CLIENT_ID, authorizationManager.getClientId());
        builder.add(ARG_CLIENT_ID, "amzn1.application-oa2-client.37f709d55e354ea6b4defad65b077f50");

        OkHttpClient client = ClientUtil.getTLS12OkHttpClient();

        Request request = new Request.Builder()
                .url(url)
                .post(builder.build())
                .build();

        final Handler handler = new Handler(Looper.getMainLooper());

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, final IOException e) {
                e.printStackTrace();
                if(callback != null){
                    //bubble up error
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            callback.onFailure(e);
                        }
                    });
                }
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                String s = response.body().string();
                if(BuildConfig.DEBUG) {
                    Log.i(TAG, s);
                }

                //get our tokens back
                final TokenResponse tokenResponse = new Gson().fromJson(s, TokenResponse.class);
                //save our tokens
                saveTokens(context, tokenResponse);
                //we have new tokens!
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        callback.onSuccess(tokenResponse.access_token);
                    }
                });
            }
        });
    }
    /**
     * Save our new tokens in SharePreferences so we can access them at a later point
     * @param context
     * @param tokenResponse
     */
    private static void firstsaveTokens(Context context, TokenResponse tokenResponse){
        //REFRESH_TOKEN = tokenResponse.refresh_token;
        //ACCESS_TOKEN = tokenResponse.access_token;
        REFRESH_TOKEN = "Atzr|IwEBIGUNInVFXdag2LbQXZrvGvhi4zfin8trYWNFpdNVE6LIIaREGcpuaH3VTIdd0_4edtqIBQN6iZB1sfFcafjam-3QuwgGfkTYr4jh9GtrNpgnvHyxaGAoA8JFB2qwE10hoEJGnu_C4YcGFZKlCG_hV7iuFPUmhXz-6EAPyeOYi7mx9whkks_dF73hBN557_fSNSpmaVho31BcmEl4-GtZE5hXvNJrYz9S17y_8zYHpnquxtQm4Ufvplw6_gzlj7foGDjaS2ZrSLWarTtEHEA_S3EdReVKG2kh6LE8vD_o-j1dzfKmRkqJYqABxFm5hyFYwdTfZcJaXhVXzWQwEF0DdHEtIJL7grjii7wUi7DOXtafT4ysBmb5Ol2HwdMAdedMA6ruKOqG4jIqESMXor9-Wvdy8SfWpwUjcZo79vNOwO-gGD5fmsaKThcfFJKxuXhUtN0tltgqNeUMjAFwLADJIzOau3V4-w9dLygmcAUEopB9vIGLrzAYpOwJxTH-_E73EKGYvGDE35ZuanOAHcXozpuJ";
        ACCESS_TOKEN = "Atza|IwEBIDGypdEEFV8J01xDz7tcfeJ2H8OuWTFtcdl_tPSlydK_NU8TJavz_mt1hLmJLJtFuCLrGLY4QqRNUuASDefZbBJQKLZT8StbZArwK5qZ8iF5usyScl99WWPAXtavCvkcJcwyy7Oc1EbGZg0RuOObdaBrbi71tXooS-mTqmd4ZOFHswFnL16A4iomsZbCRTOW2MihtqWNMNBzE0aO5-V70KiyOhjZ7LjZbGQ71sKIjY1v3JHmLm3rgoXpM9WNbJV4JUMYo1rg6-DNH5JopmRlku-sBe_0HoW3uc0mLSHEP8LFnJMAJH-Q-wtmtMWTr7HgBe0Xj43jVfrQfk7bYPxQEQz6FnbTNJyAveeoK4aJGiz8vCniD1TK-owa9UWafCsiz967mk_ECzw9ozlrVuDKHtOsBgM7hwypn1sZnLbFkLjEoCJVn6SE0W0E8M2CcFmPp9DY7R1I5IZKStqhhT_8NOxt2ZIIVDd1_QFAb8C_tSiv4tKjRk7mcEH7QesEh-ogrNlq05nxU9rUl9mMEjpIEb_R";
        Log.d(TAG, "saveTokens: REFRESH_TOKEN"+REFRESH_TOKEN+"ACCESS_TOKEN"+ACCESS_TOKEN);

        SharedPreferences.Editor preferences = Util.getPreferences(context.getApplicationContext()).edit();
        preferences.putString(PREF_ACCESS_TOKEN, ACCESS_TOKEN);
        preferences.putString(PREF_REFRESH_TOKEN, REFRESH_TOKEN);
        //comes back in seconds, needs to be milis
        preferences.putLong(PREF_TOKEN_EXPIRES, (System.currentTimeMillis() + tokenResponse.expires_in * 1000));
        preferences.commit();
    }
    /**
     * Save our new tokens in SharePreferences so we can access them at a later point
     * @param context
     * @param tokenResponse
     */
    private static void saveTokens(Context context, TokenResponse tokenResponse){
        REFRESH_TOKEN = tokenResponse.refresh_token;
        ACCESS_TOKEN = tokenResponse.access_token;
        //REFRESH_TOKEN = "Atzr|IwEBIM7J_-krLHoOKkcNcYU93IoelRFMynIxWOv7ry0T8VDOaLmbQ-PRJv3C4_oEbLsdStU5csB1oLUb2m3zAEBinGTshcpU92Qo__z314e0cIk5e0THVMnnbW9ctyBFdxaberAFfupAyqUkZHYloCxiLhLm6ew8AW9djOmYChEHnbYHmVyfIDKXhEtpHwgOSKWgDSYtr6e8MVI38x_VROr1W6tfIgh658UJZzDEfNXUax7YaQP6waLVBpTj4AQAi4Om2R43S1ECAT-QdfKpDmpkkPd7kEtYuEPY5dIfAvRuakPj5oEkyJw7k05XBaG9xnU3ADl2i7vnGiMM7lWRwY5j5xS2c7RdUyIP2rEJA69oAWa4tZub7otVdi-Y_DxhAxUR-YXtniJYs5JkogtDvY9odBUNdl84Jh14Xko0-_QB2silhd-niTCi_Pks705qX2HbkaOeoFq0E9oYznRIoGoWNTOHa0B4voiXo3v6YPPwhYiigss29mE800m0Fg0BXxeLENHFPzwwVzhgHi6v0lmqdJBxyt-vOLF2gNPs5F0Xy8CtOA";
        //ACCESS_TOKEN = "Atza|IwEBIDnB4glWbDZWG7mshORcPd7RxfEkF5NHIk4m4uLgiWRh63nZhhD6SWfmITY7jcBmp3z47bDhCZBE30FWiQzE3WyVU4egYxnBDnEOQKeQhPeXrsO540xXHG2X6II4ezLKxbbePr6WoW3zt5ShJxYaE56lJsWbcIGb2gTxouZYUoU-fkQi4Utj9yLVYvxoWkBI3E-soyKKtJY9aGHhxU6HPqNcEOyCMg1rmZppzU2IvVZ5QybWaYXqlDXCPVSED6a9oo6PDmZG7m9L0YBOTU6L3mbJEJ8oAZeZHZe5v1qti_i1o0D-B95M_j17-3S88MObhhIakNKxyNfhw8hZ9NCFrtKFJu3OolS9WqNzYNApehbo9XBNoHpqG8hPOp_Piu_kgSUp7ZJmVUd60l2rM_n44BqfS-KJ5dqsCFqo3YxWT9F6ZkaAcwtu0gRV8DjS6cA8UCADoHTZcSaWkfz2ur21-lVz1K6tOqJvxapm0vQc6HbKEZ0KVVDC6oigfuzRwyTlzONHHh1mNnyIW1p4fRBdjvu6";
        Log.d(TAG, "saveTokens: REFRESH_TOKEN"+REFRESH_TOKEN+"ACCESS_TOKEN"+ACCESS_TOKEN);

        SharedPreferences.Editor preferences = Util.getPreferences(context.getApplicationContext()).edit();
        preferences.putString(PREF_ACCESS_TOKEN, ACCESS_TOKEN);
        preferences.putString(PREF_REFRESH_TOKEN, REFRESH_TOKEN);
        //comes back in seconds, needs to be milis
        preferences.putLong(PREF_TOKEN_EXPIRES, (System.currentTimeMillis() + tokenResponse.expires_in * 1000));
        preferences.commit();
    }

    public interface TokenResponseCallback {
        void onSuccess(TokenResponse response);
        void onFailure(Exception error);
    }

    //for JSON parsing of our token responses
    public static class TokenResponse{
        public String access_token;
        public String refresh_token;
        public String token_type;
        public long expires_in;
    }

    public interface TokenCallback{
        void onSuccess(String token);
        void onFailure(Throwable e);
    }
}
