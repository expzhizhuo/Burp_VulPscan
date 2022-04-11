package burp;

import burp.poc.spring_CVE_2022_22947;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.List;
import java.util.Vector;

public class BurpExtender implements IBurpExtender, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private Tags tags;
    private List<Tags.LogEntry> log;
    private List<String> spring_CVE_2022_22947_urls = new Vector();
    private int id = 0;

    //
    // 实现IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 保留对回调对象的引用
        this.callbacks = callbacks;

        // 获取扩展助手对象
        this.helpers = callbacks.getHelpers();
        this.tags = new Tags(callbacks, helpers);
        this.log = tags.log;
        callbacks.registerHttpListener(this);


        callbacks.printOutput("By:F6JO\nGithub: https://github.com/F6JO\n\nVulnerability list:\n    CVE-2022-22947");
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {


        // 只处理响应
        if (!messageIsRequest) {
            IHttpRequestResponse NewMessageInfo = null;
            String url = Handle_URL(helpers.analyzeRequest(messageInfo).getUrl().toString());
            URL Url = Get_URL(url);
            String Method = null;
            int Status_code = 0;
            String Vul = null;
            boolean panduan = false;


            if (!spring_CVE_2022_22947_urls.contains(url)) {
                spring_CVE_2022_22947_urls.add(url);
                IHttpRequestResponse jieguo = spring_CVE_2022_22947.poc(url, messageInfo, helpers, callbacks);
                int zhuangtai = helpers.analyzeResponse(jieguo.getResponse()).getStatusCode();
                if (jieguo != null && zhuangtai >= 200 &&
                        zhuangtai < 300 &&
                        helpers.bytesToString(jieguo.getResponse()).contains("AddResponseHeader Result")) {
                    NewMessageInfo = jieguo;
                    Method = helpers.analyzeRequest(NewMessageInfo.getRequest()).getMethod();
                    Status_code = zhuangtai;
                    Vul = "Spring CVE-2022-22947";
                    panduan = true;
                    id += 1;

                }
            }


            if (panduan) {
                synchronized (log) {
                    int row = log.size();
                    // id url RequestMothed StatusCode Vul Time
                    // IHttpRequestResponsePersisted
                    log.add(new Tags.LogEntry(callbacks.saveBuffersToTempFiles(NewMessageInfo), id,
                            Url, Method, Status_code, Vul, new Date().toString()));
                    tags.fireTableRowsInserted(row, row);
                }
            }


        }

    }

    public static URL Get_URL(String url) {
        try {
            return new URL(url);
        } catch (MalformedURLException e) {
            return null;
        }
    }

    public String Handle_URL(String url) {
        int weizhi = url.lastIndexOf(":");
        for (int i = 0; i < 10; i++) {
            if (url.charAt(weizhi + i) == '/') {
                url = url.substring(0, weizhi + i);
                break;
            }
        }

        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        //        callbacks.printOutput(url);
        return url;
    }
}