package burp;

import java.awt.Component;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class Tags extends AbstractTableModel implements  ITab, IMessageEditorController {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    public final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;

    private JSplitPane top;

    //
    // 实现IBurpExtender
    //

    public Tags(IBurpExtenderCallbacks callbacks,IExtensionHelpers help) {
        // 保留对回调对象的引用
        this.callbacks = callbacks;

        // 获取扩展助手对象
        this.helpers = help;

        // 设置我们的分机名
        callbacks.setExtensionName("Custom logger");

        // 创建我们的用户界面
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // 创建最上面的一层
                top = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                // 创建容器，容器可以加入多个页面
                JTabbedPane tabs = new JTabbedPane();
                // 创建主拆分窗格
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                // 日志条目表
                Table logTable = new Table(Tags.this);
                JScrollPane scrollPane = new JScrollPane(logTable);

//                 创建请求和响应的展示窗
                JSplitPane HjSplitPane = new JSplitPane();
                HjSplitPane.setDividerLocation(0.5D);

                // 创建请求/响应的子选项卡
                JTabbedPane Request_tabs = new JTabbedPane();
                JTabbedPane Response_tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(Tags.this, false);
                responseViewer = callbacks.createMessageEditor(Tags.this, false);
                Request_tabs.addTab("Request", requestViewer.getComponent());
                Response_tabs.addTab("Response", responseViewer.getComponent());

                // 将子选项卡添加进主选项卡
                HjSplitPane.add(Request_tabs,"left");
                HjSplitPane.add(Response_tabs,"right");

                // 将日志条目表和展示窗添加到主拆分窗格
                splitPane.add(scrollPane,"left");
                splitPane.add(HjSplitPane,"right");

                // 将两个页面插入容器
                tabs.addTab("VulDisplay",splitPane);
//                tabs.addTab("ceshi2",new gui().$$$getRootComponent$$$());

                // 将容器置于顶层
                top.setTopComponent(tabs);

                // 定制我们的UI组件
                callbacks.customizeUiComponent(top);

                // 将自定义选项卡添加到Burp的UI
                callbacks.addSuiteTab(Tags.this);

            }
        });
    }

    //
    // 实施ITab
    //

    @Override
    public String getTabCaption() {
        return "Logger";
    }

    @Override
    public Component getUiComponent() {
        return top;
    }



    //
    // 扩展AbstractTableModel
    //

    @Override
    public int getRowCount() {
        return log.size();
    }

    // 设置总共有几列
    @Override
    public int getColumnCount() {
        return 6;
    }

    // 设置每个列的名称
    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {

            case 0:
                return "Id";
            case 1:
                return "URL";
            case 2:
                return "RequestMothed";
            case 3:
                return "StatusCode";
            case 4:
                return "Vul";
            case 5:
                return "Time";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = log.get(rowIndex);
        // 设置每个条目的每一列的值
        switch (columnIndex) {
            case 0:
                return String.valueOf(logEntry.Id);
            case 1:
                return logEntry.url.toString();
            case 2:
                return logEntry.RequestMothed;
            case 3:
                return String.valueOf(logEntry.StatusCode);
            case 4:
                return logEntry.Vul;
            case 5:
                return logEntry.Time;

            default:
                return "";
        }
    }

    //
    // 实现IMessageEditorController
    // 这使我们的请求/响应查看器能够获得有关所显示消息的详细信息
    //

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    //
    // 扩展JTable以处理单元格选择
    //

    private class Table extends JTable {
        public Table(TableModel tableModel) {
            super(tableModel);
        }
        // 当条目被点击时触发
        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            // 显示所选行的日志条目
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    //
    // 类来保存每个日志条目的详细信息
    //

    public static class LogEntry {
        final IHttpRequestResponsePersisted requestResponse;
        final int Id;
        final URL url;
        final String RequestMothed;
        final int StatusCode;
        final String Vul;
        final String Time;

        LogEntry(IHttpRequestResponsePersisted requestResponse, int id, URL url, String RequestMothed, int StatusCode, String Vul, String Time) {
            this.requestResponse = requestResponse;
            this.Id = id;
            this.url = url;
            this.RequestMothed = RequestMothed;
            this.StatusCode = StatusCode;
            this.Vul = Vul;
            this.Time = Time;

        }
    }
}