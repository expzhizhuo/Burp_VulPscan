package burp;


import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class HttpsRequest {
    /**
     * 向指定URL发送GET方法的请求
     *
     * @param url
     *            发送请求的URL
     * @param param
     *            请求参数，请求参数应该是 name1=value1&name2=value2 的形式。
     * @return URL 所代表远程资源的响应结果
     */
    public static Map<String, String> sendGet(String url, String param, Map<String,String> headers) {
        String result = "";
        Map<String, Object> zidian = new LinkedHashMap<String,Object>();
        BufferedReader in = null;
        try {
            String urlNameString = url + "?" + param;
            URL realUrl = new URL(urlNameString);
            URLConnection urlConnection;
            // 打开和URL之间的连接
            if (url.startsWith("https")) {
                HttpsURLConnection connection = (HttpsURLConnection) realUrl.openConnection();
                connection.setHostnameVerifier(new TrustAnyHostnameVerifier());
                urlConnection =(URLConnection) connection;
            }else {
                urlConnection = realUrl.openConnection();
            }
            // 设置通用的请求属性
            for (String key : headers.keySet()){
                urlConnection.setRequestProperty(key,headers.get(key));
            }
            // 建立实际的连接
            urlConnection.connect();
            // 获取所有响应头字段
            Map<String, List<String>> map = urlConnection.getHeaderFields();
            // 遍历所有的响应头字段
            for (String key : map.keySet()) {
//                System.out.println(key + "--->" + map.get(key).getClass().toString());
//                System.out.println(key + "--->" + map.get(key));
                if (key == null){
                    zidian.put("http", map.get(key));
                    continue;
                }
                zidian.put(key, map.get(key));
            }
            // 定义 BufferedReader输入流来读取URL的响应
            try {
                in = new BufferedReader(new InputStreamReader(
                        urlConnection.getInputStream(), StandardCharsets.UTF_8));
            } catch (IOException e) {
                return null;
            }

            String line;
            while ((line = in.readLine()) != null) {
                result += line;

            }
        } catch (Exception e) {
            System.out.println("发送GET请求出现异常！" + e);
            e.printStackTrace();
        }
        // 使用finally块来关闭输入流
        finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        zidian.put("result",result);
        return handle(zidian);
//        return null;
    }

    /**
     * 向指定 URL 发送POST方法的请求
     *
     * @param url
     *            发送请求的 URL
     * @param param
     *            请求参数，请求参数应该是 name1=value1&name2=value2 的形式。
     * @return 所代表远程资源的响应结果
     */
    public static Map<String, String> sendPost(String url, String param, Map<String,String> headers) {
        PrintWriter out = null;
        BufferedReader in = null;
        String result = "";
        Map<String, Object> zidian = new LinkedHashMap<String,Object>();
        try {
            URL realUrl = new URL(url);
            // 打开和URL之间的连接
            URLConnection conn;
            // 打开和URL之间的连接
            if (url.startsWith("https")) {
                HttpsURLConnection connection = (HttpsURLConnection) realUrl.openConnection();
                connection.setHostnameVerifier(new TrustAnyHostnameVerifier());
                conn = connection;
            }else {
                conn = realUrl.openConnection();
            }
            // 设置通用的请求属性
            for (String key : headers.keySet()){
                conn.setRequestProperty(key,headers.get(key));
            }
            // 发送POST请求必须设置如下两行
            conn.setDoOutput(true);
            conn.setDoInput(true);
            // 获取URLConnection对象对应的输出流
            out = new PrintWriter(conn.getOutputStream());
            // 发送请求参数
            out.print(param);
            // flush输出流的缓冲
            out.flush();
            // 定义BufferedReader输入流来读取URL的响应
            try {
                in = new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
            } catch (IOException e) {
                return null;
            }
            // 获取响应头
            Map<String, List<String>> map = conn.getHeaderFields();
            // 遍历所有的响应头字段
            for (String key : map.keySet()) {
//                System.out.println(key + "--->" + map.get(key));
                if (key == null){
                    zidian.put("http", map.get(key));
                    continue;
                }
                zidian.put(key, map.get(key));
            }

            String line;
            while ((line = in.readLine()) != null) {
                result += line;
            }
        } catch (Exception e) {
            System.out.println("发送 POST 请求出现异常！"+e);
            e.printStackTrace();
        }
        //使用finally块来关闭输出流、输入流
        finally{
            try{
                if(out!=null){
                    out.close();
                }
                if(in!=null){
                    in.close();
                }
            }
            catch(IOException ex){
                ex.printStackTrace();
            }
        }
        zidian.put("result",result);
        return handle(zidian);
//        return null;
    }


    public static Map<String, String> handle(Map<String, Object> fanhui){
        String http = "";
        String code = "";
        String head = "";
        String body = (String) fanhui.get("result");
        Map<String,String> jieguo = new LinkedHashMap<String,String>();
        for (String i : (List<String>)fanhui.get("http")){
            List<String> fenge = Arrays.asList(i.split(" "));
            http = fenge.get(0).trim();
            code = fenge.get(1).trim();
        }
        for (String i : fanhui.keySet()){
            String value = "";
            if (!i.equals("http") && !i.equals("result")) {
                for (String a :  (List<String>)fanhui.get(i)){
                    value += a+"\n";
                }
                head += i + ":"+value;
            }

        }
        jieguo.put("http",http);
        jieguo.put("code",code);
        jieguo.put("head",head);
        jieguo.put("body",body);
        return jieguo;

    }

}


class TrustAnyHostnameVerifier implements HostnameVerifier {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
}