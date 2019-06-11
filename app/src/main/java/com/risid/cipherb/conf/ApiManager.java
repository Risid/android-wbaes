package com.risid.cipherb.conf;

import com.jakewharton.retrofit2.adapter.rxjava2.RxJava2CallAdapterFactory;
import com.risid.cipherb.service.RetrofitService;

import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

public class ApiManager {

    private RetrofitService orderApi;
    private static ApiManager sApiManager;
    private String baseUrl;

    public static ApiManager getInstence() {
        if (sApiManager == null) {
            synchronized (ApiManager.class) {
                if (sApiManager == null) {
                    sApiManager = new ApiManager();
                }
            }
        }
        return sApiManager;
    }
    public RetrofitService getOrderApi(String url) {

        if (orderApi == null || url.equals(baseUrl)) {
            Retrofit retrofit = new Retrofit.Builder()
                    .baseUrl(url)
                    .addCallAdapterFactory(RxJava2CallAdapterFactory.create())
                    .addConverterFactory(GsonConverterFactory.create())
                    .build();
            orderApi = retrofit.create(RetrofitService.class);
            baseUrl = url;
        }
        return orderApi;
    }
}