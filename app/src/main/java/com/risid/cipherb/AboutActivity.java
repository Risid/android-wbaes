package com.risid.cipherb;

import android.graphics.Color;
import android.os.Bundle;
import android.widget.FrameLayout;

import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.RecyclerView;

import com.artitk.licensefragment.RecyclerViewLicenseFragment;
import com.artitk.licensefragment.ScrollViewLicenseFragment;
import com.artitk.licensefragment.model.CustomUI;
import com.artitk.licensefragment.model.License;
import com.artitk.licensefragment.model.LicenseID;
import com.artitk.licensefragment.model.LicenseType;
import com.trello.rxlifecycle3.components.RxActivity;
import com.trello.rxlifecycle3.components.RxFragment;

import java.util.ArrayList;

import butterknife.BindView;
import butterknife.ButterKnife;

public class AboutActivity extends FragmentActivity {

    @BindView(R.id.rv_license)
    FrameLayout rvLicense;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_about);
        ButterKnife.bind(this);

        ArrayList<Integer> licenseIds = new ArrayList<>();
        licenseIds.add(LicenseID.GSON);                             // Add License ID from LicenseID class
        licenseIds.add(LicenseID.RETROFIT);
        licenseIds.add(LicenseID.OKHTTP);
        ArrayList<License> customLicenses = new ArrayList<>();

        customLicenses.add(new License(this, "RxJava", LicenseType.APACHE_LICENSE_20,      "2004",      "RxJava"));

        customLicenses.add(new License(this, "RxJava", LicenseType.APACHE_LICENSE_20,      "2004",      "RxJava"));
        RecyclerViewLicenseFragment fragment = RecyclerViewLicenseFragment.newInstance(licenseIds);
        fragment.addCustomLicense(customLicenses);
        CustomUI customUI = new CustomUI()                          // Create Customize UI from CustomUI class
                .setTitleBackgroundColor(getResources().getColor(R.color.colorPrimary))
                .setTitleTextColor(getResources().getColor(R.color.colorAccent))
                .setLicenseBackgroundColor(getResources().getColor(R.color.colorPrimary))
                .setLicenseTextColor(getResources().getColor(R.color.colorPrimaryDark));

        fragment.setCustomUI(customUI);

        this.getFragmentManager().beginTransaction()
                .add(R.id.rv_license, fragment, "f1")
                .commit();



    }
}
