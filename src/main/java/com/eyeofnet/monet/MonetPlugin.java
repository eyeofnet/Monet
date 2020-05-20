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


import java.awt.Color;

import javax.swing.Icon;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GraphService;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.graph.GraphData;
import ghidra.program.model.graph.GraphDisplay;
import ghidra.program.model.graph.GraphSelectionHandler;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.GraphException;
import resources.Icons;


// status = PluginStatus.RELEASED
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.GRAPH,
	shortDescription = "Graph Service",
	description = "Implements the Ghidra GraphService interface.",
    servicesRequired = {ConsoleService.class},
	servicesProvided = {GraphService.class}
)
//@formatter:on

public class MonetPlugin extends ProgramPlugin implements GraphService
{
    public final static String COLOR_RED = "Red";
    public final static String COLOR_BLUE = "Blue";
    public final static String COLOR_DARK_GREEN = "DarkGreen";
    public final static String COLOR_ORANGE = "Orange";
    public final static String COLOR_DARK_ORANGE = "DarkOrange";
    public final static String COLOR_BLACK = "Black";
    
    // FIXME: This Icon will probably move at some point in the future, and it's a dumb picture anyway...
    static final Icon PROVIDER_ICON = Icons.ARROW_UP_LEFT_ICON;
	
	private MonetProvider provider;
	private MonetDisplay display = null;
	

	//private final static String TAG = "MonetPlugin";

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public MonetPlugin(PluginTool tool) {
		super(tool, true, true);

		String pluginName = getName();
		provider = new MonetProvider(this,pluginName);
		display = new MonetDisplay(this);
	}

	public MonetProvider getProvider()
	{
		return provider;
	}
	
	public MonetDisplay getDisplay()
	{
		return display;
	}
	
	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}

	@Override
	public GraphData createGraphContent() {
		return new MonetData();
	}

	@Override
	public GraphDisplay getGraphDisplay(boolean newDisplay) throws GraphException {
		if (newDisplay) {
			display = new MonetDisplay(this);
		}
		return display;
	}

	@Override
	public GraphDisplay getGraphDisplay() throws GraphException {
		return display;
	}

	@Override
	public void setSelection(Object selection) {
		//ConsoleService cs = getConsoleService();
		//cs.addMessage(TAG,"[setSelection] selection = " + selection.toString());
	}

	@Override
	public void setLocation(Object location) {
		//ConsoleService cs = getConsoleService();
		//cs.addMessage(TAG,"[setLocation] location = " + location.toString());		
	}

	@Override
	public void fireSelectionEvent(Object selection) {
		//ConsoleService cs = getConsoleService();
		//cs.addMessage(TAG,"[fireSelectionEvent] selection = " + selection.toString());		
	}

	@Override
	public void fireLocationEvent(Object location) {
		//ConsoleService cs = getConsoleService();
		//cs.addMessage(TAG,"[fireLocationEvent] location = " + location.toString());		
	}

	@Override
	public boolean fireNotificationEvent(String notificationType, GraphSelectionHandler handler) {
		//ConsoleService cs = getConsoleService();
		//cs.addMessage(TAG,"[fireNotificationEvent] type = " + notificationType);		
		return false;
	}
	
    @Override
    protected void locationChanged(ProgramLocation loc) {
		//ConsoleService cs = getConsoleService();
		//cs.addMessage(TAG,"[locationChanged] loc = " + loc);
    }

    @Override
    protected void programActivated(Program program) {
		//ConsoleService cs = getConsoleService();
		//cs.addMessage(TAG,"[programActivated] program = " + program);		
    }

    @Override
    protected void programDeactivated(Program program) {
		//ConsoleService cs = getConsoleService();
		//cs.addMessage(TAG,"[programDeactivated] program = " + program);		
    }

    @Override
    protected void programClosed(Program program) {
		//ConsoleService cs = getConsoleService();
		//cs.addMessage(TAG,"[programClosed] program = " + program);		
    }
    
    public static Color getColorFromName(String name) {
        Color rv = new Color(0,0,0);

        if (null != name) {
            if (name.contentEquals(COLOR_RED)) {
                rv = new Color(0xDC,0x14,0x3C);
            } else if (name.contentEquals(COLOR_BLUE)) {
                rv = new Color(0xAD,0xD8,0xE6);
            } else if (name.contentEquals(COLOR_DARK_GREEN)) {
                rv = new Color(0x55,0x6B,0x2F);
            } else if (name.contentEquals(COLOR_ORANGE)) {
                rv = new Color(0xff,0xA5,0x00);
            } else if (name.contentEquals(COLOR_DARK_ORANGE)) {
                rv = new Color(0xFF,0x8C,0x00);
            } else if (name.contentEquals(COLOR_BLACK)) {
                rv = new Color(0x80,0x80,0x80);
            } else {
            	rv = Color.WHITE;
            }
        }
        return rv;
    }

    ConsoleService getConsoleService() {
        return tool.getService(ConsoleService.class);
    }

}

