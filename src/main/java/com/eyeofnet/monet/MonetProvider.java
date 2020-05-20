/***************************************************************************
 * Copyright 2020 Winslow Williams 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. 
 ***************************************************************************/

package com.eyeofnet.monet;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Point;
import java.util.Collection;
import java.util.Iterator;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.graph.GraphData;
import ghidra.program.model.graph.GraphDisplay;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
import resources.Icons;

import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.SparseMultigraph;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.algorithms.layout.FRLayout;
import edu.uci.ics.jung.algorithms.layout.KKLayout;
import edu.uci.ics.jung.algorithms.layout.ISOMLayout;
import edu.uci.ics.jung.algorithms.layout.CircleLayout;
import edu.uci.ics.jung.algorithms.layout.SpringLayout;

//import edu.uci.ics.jung.visualization.BasicVisualizationServer;
import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.renderers.Renderer.VertexLabel.Position;
import edu.uci.ics.jung.visualization.control.ModalGraphMouse;
import edu.uci.ics.jung.visualization.control.DefaultModalGraphMouse;


class MonetProvider extends ComponentProvider implements OptionsChangeListener {

	private int current_layout_type = SelectLayoutDialog.int_ISOM_layout;
	private Font vfont;
	private Font vfont_override = null;
    private VertexLabelInfo label_info;
    private MonetPanel graph_panel;
	private MonetPlugin plugin;
	private PluginTool tool;
	private Graph<MonetVertex,MonetEdge> internal_graph = null;
	
	private HelpLocation help;
	// private String topicName;

	
	private static final Font DEFAULT_FONT = new Font(Font.MONOSPACED, Font.PLAIN, 10);
	private static final String VFONT_OPTION_LABEL = "VFont";
    private static final String VFONT_DESCRIPTION = "Font for Vertex labels";

	private static final String TAG = "MonetProvider";

	public MonetProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = (MonetPlugin) plugin;
		tool = plugin.getTool();
		buildPanel();
		createOptions();
		createActions();
	}
	
	public void setGraphData(GraphData data)
	{
		MonetData mdata = (MonetData) data;
		internal_graph = new SparseMultigraph<MonetVertex,MonetEdge>();
		
		Iterator<MonetVertex> viter = mdata.getVertices();
		while (viter.hasNext()) {
			internal_graph.addVertex(viter.next());
		}
		Iterator<MonetEdge> eiter = mdata.getEdges();
		while (eiter.hasNext()) {
			MonetEdge edge = eiter.next();
			internal_graph.addEdge(edge,(MonetVertex) edge.getStart(),(MonetVertex) edge.getEnd());
		}
		// If we call it here, we update before the ASTGraphTask is finished configuring us.
		//updateGraph();
	}
	
	public void updateGraph()
	{
		int pwidth = graph_panel.getWidth();
		int pheight = graph_panel.getHeight();
        int fwidth = pwidth - pwidth/10;
        int fheight = pheight - pheight/10;
        Layout<MonetVertex,MonetEdge> layout;
        MonetDisplay display;

        ConsoleService cs = plugin.getConsoleService();

        display = plugin.getDisplay();
        if (null == display) {
            if (null != cs) {
            	cs.addMessage(TAG, "Display is null!");
            }
        	label_info = new VertexLabelInfo();
        } else {
        	label_info = display.getVertexLabelInfo();
        }
        
        if (null != internal_graph) {
        	Collection<MonetVertex> col = internal_graph.getVertices();
        	Iterator<MonetVertex> iter = col.iterator();
        	while (iter.hasNext()) {
        		MonetVertex vtx = iter.next();
        		vtx.setLabelAttributeName(label_info.getAttrName());
        	}
        
            switch (current_layout_type) {
        	    case SelectLayoutDialog.int_FR_layout:
        		    layout = new FRLayout<MonetVertex,MonetEdge>(internal_graph);
        		    break;
        	    case SelectLayoutDialog.int_KK_layout:
        		    layout = new KKLayout<MonetVertex,MonetEdge>(internal_graph);
        		    break;
        	    case SelectLayoutDialog.int_ISOM_layout:
        		    layout = new ISOMLayout<MonetVertex,MonetEdge>(internal_graph);
        		    break;
        	    case SelectLayoutDialog.int_Circle_layout:
        		    layout = new CircleLayout<MonetVertex,MonetEdge>(internal_graph);
        		    break;
                default:
                    layout = new SpringLayout<MonetVertex,MonetEdge>(internal_graph);
                    break;
            }
        
            vfont_override = null;
            if (false == label_info.shouldUseDefaultFont()) {
        	    if (label_info.isMonospace()) {
        		    vfont_override = new Font(Font.MONOSPACED, Font.PLAIN, label_info.getSize());
        	    } else {
        		    vfont_override = new Font(Font.SANS_SERIF, Font.PLAIN, label_info.getSize());        		
        	    }
            }
        
            layout.setSize(new Dimension(fwidth,fheight));
      
            VisualizationViewer<MonetVertex,MonetEdge> vv =
            new VisualizationViewer<MonetVertex,MonetEdge>(layout);
            vv.setPreferredSize(new Dimension(pwidth,pheight));
            vv.setLocation(new Point(fwidth/2,fheight/2));
            vv.getRenderContext().setVertexIconTransformer(p -> p.getIcon());
            vv.getRenderContext().setVertexFillPaintTransformer(p -> p.getColor());
            vv.getRenderContext().setVertexLabelTransformer(p -> getLabel(p));
            vv.getRenderContext().setVertexFontTransformer(p -> getFont(p));
            switch (label_info.getAlignment()) 
            {
        	    case GraphDisplay.ALIGN_LEFT:
                    vv.getRenderer().getVertexLabelRenderer().setPosition(Position.W);
                    break;
                case GraphDisplay.ALIGN_RIGHT:
                    vv.getRenderer().getVertexLabelRenderer().setPosition(Position.E);
                    break;
                default:
                    vv.getRenderer().getVertexLabelRenderer().setPosition(Position.CNTR);
                    break;
            }
            // Create a graph mouse and add it to the visualization component
            DefaultModalGraphMouse<MonetVertex,MonetEdge> gm = new DefaultModalGraphMouse<MonetVertex,MonetEdge>();
            gm.setMode(ModalGraphMouse.Mode.TRANSFORMING);
            vv.setGraphMouse(gm);
		    graph_panel.removeAll();
		    graph_panel.add(vv);
		    graph_panel.revalidate();
        }
	}
	
	private Font getFont(MonetVertex v) {
		if (null != vfont_override) {
			return vfont_override;
		}
		return vfont;
	}
	
	private String getLabel(MonetVertex v) {
		String rv = "";
		int max_lines = label_info.getMaxLines();
		if (max_lines > 1) {
			int head = 0;
			int remaining;
			int line_length;
			String s = v.toString();
			StringBuilder sb = new StringBuilder();
			sb.append("<html>");

			remaining = s.length();
			line_length = remaining/(max_lines-1);
			while (remaining > 0) {
				if (remaining < line_length) {
					line_length = remaining;
				}
				sb.append(s.substring(head,head+line_length));
				sb.append("<br>");
				head += line_length;
				remaining -= line_length;
			}
			sb.append("</html>");
			rv = sb.toString();
			
	        ConsoleService cs = plugin.getConsoleService();
			if (null != cs) {
				cs.addMessage(TAG,s);
				cs.addMessage(TAG,rv);
			}
		} else {
			rv = v.toString();
		}
		return rv;
	}

	// Customize GUI
	private void buildPanel() {
		graph_panel = new MonetPanel(this,new BorderLayout());
		setVisible(true);
	}
	
	private void createOptions() {

        ToolOptions options = tool.getOptions("Monet");
		// TODO: Customize help (or remove if help is not desired)
        // HelpLocation.buildURL is broken - it needs to create relative paths, not just absolute paths.
        // For now, we just comment the help out...
		topicName = "monet";
		
		//String anchorName = "HelpAnchor";
		//help = new HelpLocation(topicName, anchorName);
		
		//setHelpLocation(help);
		//options.setOptionsHelpLocation(help);
        options.registerOption(VFONT_OPTION_LABEL, DEFAULT_FONT, help, VFONT_DESCRIPTION);
        vfont = options.getFont(VFONT_OPTION_LABEL, DEFAULT_FONT);
        vfont = SystemUtilities.adjustForFontSizeOverride(vfont);

		options.addOptionsChangeListener(this);
	}

	// Customize actions
	private void createActions() {
		DockingAction action;
		action = new DockingAction("Set Graph Layout", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				SelectLayoutDialog dialog = new SelectLayoutDialog("Select graph layout",current_layout_type);
				tool.showDialog(dialog);
				
				int selected_type = dialog.getSelectedLayoutType();
				if (selected_type > -1) {
					if (current_layout_type != selected_type) {
						current_layout_type = selected_type;
						updateGraph();
					}
				}
			}
		};
		
		action.setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
		
		action = new DockingAction("Refresh Graph", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				updateGraph();
			}
		};
		action.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
	}

    @Override
    public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
            Object newValue) {
        if (optionName.equals(VFONT_OPTION_LABEL)) {
            vfont = SystemUtilities.adjustForFontSizeOverride((Font) newValue);
        }
        if (isVisible()) { 
        	updateGraph();
        }
    }

	@Override
	public JComponent getComponent() {
		return graph_panel;
	}

    public void componentActivated() {
    	updateGraph();
    }    
}

