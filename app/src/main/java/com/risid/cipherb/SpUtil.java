package com.risid.cipherb;

import android.content.Context;
import android.content.SharedPreferences;

public class SpUtil {
    private SharedPreferences sharedPreferences;
    private static final String SHARE_PREFERENCES = "set";
    private static final String URL = "url";
    private static final String ID = "id";
    private static final String TOKEN = "token";
    private static final String IV = "iv";

    public SpUtil(Context context) {
        this.sharedPreferences = context.getSharedPreferences(SHARE_PREFERENCES, Context.MODE_PRIVATE);
    }

    public void setURL(String url){
        sharedPreferences.edit().putString(URL, url).apply();
    }

    public void setToken(String token){
        sharedPreferences.edit().putString(TOKEN, token).apply();
    }

    public void setID(String id){
        sharedPreferences.edit().putString(ID, id).apply();
    }

    public void setIV(String iv){
        sharedPreferences.edit().putString(IV, iv).apply();
    }

    public String getToken(){
        return sharedPreferences.getString(TOKEN, null);
    }

    public String getURL(){
        return sharedPreferences.getString(URL, null);
    }
    public String getID(){
        return sharedPreferences.getString(ID, null);
    }
    public String getIV(){
        return sharedPreferences.getString(IV, null);
    }




}
