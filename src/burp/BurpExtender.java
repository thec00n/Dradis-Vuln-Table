package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JComboBox;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;

/**
 * Dradis Vuln Table extension for burp suite.
 * @author Gerhard Wagner / www.vantagepoint.sg
 *
 */

public class BurpExtender implements ITab, IContextMenuFactory{
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private JPanel main; 
	private JPanel menu;
	private JTabbedPane tPane;
	private JComboBox tabs;
	private final String TAB_NAME = "Dradis Vuln Tables";	
	public static String MENU_ITEM_TEXT = "Generate Dradis Vuln Table";

	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		this.callbacks = callbacks;
	
		helpers = callbacks.getHelpers();
	
		callbacks.registerContextMenuFactory(this);
	
		callbacks.setExtensionName("Dradis Vuln Tables");
		main = new JPanel(new BorderLayout());
		menu = new JPanel();
		menu.setPreferredSize(new Dimension(0, 500));
		tPane = new JTabbedPane();
		main.add(menu, BorderLayout.LINE_START);
		main.add(tPane, BorderLayout.CENTER);
		callbacks.customizeUiComponent(main);
		tabs = new JComboBox();
		callbacks.addSuiteTab(BurpExtender.this);
	}

	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {

		final IScanIssue issues[] = invocation.getSelectedIssues();
		List<JMenuItem> ret = new LinkedList<JMenuItem>();
		JMenuItem menuItem = new JMenuItem(MENU_ITEM_TEXT);

		menuItem.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent arg0) {
				if(arg0.getActionCommand().equals(MENU_ITEM_TEXT)){
					final JTextArea serverTab = new JTextArea(5, 100);
					serverTab.setEditable(true);
					serverTab.append("Generated Dradis Vuln Table: \n\n");
					JScrollPane scrollWindow = new JScrollPane(serverTab);
					scrollWindow.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
					scrollWindow.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
					scrollWindow.setPreferredSize(tPane.getSize());
					
					/*
					 *  Sample Dradis table
					 * |_. Username |_. Password |_. Role |
					 * | pentest1 | Password1!! | Administrator |
					 * | pentest2 | Password2!! | Moderator |
                     * | pentest3 | Password3!! | User |
					 */
					
					serverTab.append("|_. URL |_. Parameter |\n");
					
					/*
					 * Burp's issue detail seems to vary a lot from issue to issue. Table generation has
					 * been implemented so far only for issues that include the parameter in the issue detail
					 * like SQL Injection or Cross Site Scripting.
					 * 
					 */
					
					//if (issues[0].getIssueName() == "SQL injection" || issues[0].getIssueName() == "Cross-site scripting (reflected)"){
						for (int i = 0; i < issues.length; i++){
							String i_d = issues[i].getIssueDetail();
							Pattern p = Pattern.compile("<b>(\\w+)</b>");
					        Matcher m = p.matcher(i_d);
					        
					        if (m.find()){
						        serverTab.append("| ");
								serverTab.append(issues[i].getUrl().getPath() + " | "+ m.group(1) );
								serverTab.append(" |\n");
					        }
						}
					//}
										
					tabs.addItem(issues[0].getUrl().getHost() + " - " + issues[0].getIssueName());
					tPane.addTab(issues[0].getUrl().getHost() + " - " + issues[0].getIssueName(), scrollWindow);
					tPane.setTabComponentAt(tPane.getTabCount() - 1,new Tab(tPane, this));
					
					

				}
			}
		});

		ret.add(menuItem);
		return(ret);

	}

	
	
	public void RemoveTab(int index) {
		String name = tPane.getTitleAt(index);
		tabs.removeItem(name);
		tPane.remove(index);
	}

	
	@Override
	public String getTabCaption() {
		return TAB_NAME;
	}

	@Override
	public Component getUiComponent() {
		return main;
	}
	
}
