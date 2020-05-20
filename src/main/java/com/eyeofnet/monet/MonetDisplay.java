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

import ghidra.program.model.graph.GraphData;
import ghidra.program.model.graph.GraphDisplay;
import ghidra.program.model.graph.GraphSelectionHandler;
import ghidra.util.exception.GraphException;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.services.ConsoleService;

public class MonetDisplay implements GraphDisplay {

	private boolean valid = false;
	private MonetPlugin plugin;
	private MonetProvider provider;
	private GraphSelectionHandler sel_handler;
	private VertexLabelInfo label_info;

	private final static String TAG = "MonetDisplay";

	
	public MonetDisplay(MonetPlugin plugin)
	{
		this.plugin = plugin;
		sel_handler = null;
		label_info = new VertexLabelInfo();
	}
	
	@Override
	public void popup() throws GraphException {
		PluginTool tool = plugin.getTool();
		provider = plugin.getProvider();
		if ((null != tool) && (null != provider)) {
			provider.updateGraph();
			tool.toFront(provider);
		}

	}

	@Override
	public void clear() throws GraphException {
		ConsoleService cs = plugin.getConsoleService();
		if (null != cs) {
			cs.addMessage(TAG,"[clear] ");
		}
	}

	@Override
	public void close() {
		ConsoleService cs = plugin.getConsoleService();
		if (null != cs) {
			cs.addMessage(TAG,"[close] ");
		}

	}

	@Override
	public boolean isValid() {
		return valid;
	}

	@Override
	public void setGraphData(GraphData graph) throws GraphException {
		provider = plugin.getProvider();
		provider.setGraphData(graph);
		valid = true;
	}
	
	@Override
	public void defineEdgeAttribute(String attributeName) throws GraphException {
		ConsoleService cs = plugin.getConsoleService();
		if (null != cs) {
			cs.addMessage(TAG,"[defineEdgeAttribute] " + attributeName);
		}
	}

	@Override
	public void defineVertexAttribute(String attributeName) throws GraphException {
		ConsoleService cs = plugin.getConsoleService();
		if (null != cs) {
			cs.addMessage(TAG,"[defineVertexAttribute] " + attributeName);
		}
	}

	@Override
	public void setVertexLabel(String attributeName, int alignment, int size, boolean monospace, int maxLines)
			throws GraphException {
		label_info.setAttrName(attributeName);
		label_info.setAlignment(alignment);
		label_info.setSize(size);
		label_info.setMaxLines(maxLines);
		label_info.setMonospace(monospace);
		label_info.useDefaultFont(false);
	}
	
	public VertexLabelInfo getVertexLabelInfo()
	{
		return label_info;
	}

	@Override
	public void setSelectionHandler(GraphSelectionHandler handler) {
		sel_handler = handler;
		sel_handler.setEnabled(true);
		sel_handler.setActive(true);
	}
	
	public GraphSelectionHandler getSelectionHandler()
	{
		return sel_handler;
	}

	@Override
	public void select(Object selectionObject, boolean global) {
		ConsoleService cs = plugin.getConsoleService();
		if (null != cs) {
			cs.addMessage(TAG,"[select] object = " + selectionObject.toString() + ", global = " + global);
		}
	}

	@Override
	public void locate(Object locationObject, boolean global) {
		ConsoleService cs = plugin.getConsoleService();
		if (null != cs) {
			cs.addMessage(TAG,"[locate] object = " + locationObject.toString() + ", global = " + global);
		}
	}

}

