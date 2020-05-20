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

import ghidra.program.model.graph.GraphDisplay;

public class VertexLabelInfo
{
	private String attr_name;
	private int alignment;
	private int size;
	private boolean monospace;
	private boolean default_font;
	private int max_lines;
		
	public VertexLabelInfo()
	{
		// If attr_name is null, the vertex name should be used 
		attr_name = null;
		alignment = GraphDisplay.ALIGN_CENTER;
		size = 12;
		monospace = true;
		max_lines = 1;
		default_font = true;
	}
		
	public String getAttrName()
	{
		return attr_name;
	}
	
	public void setAttrName(String v)
	{
		attr_name = v;
	}
	
	public int getAlignment()
	{
		return alignment;
	}
	
	public void setAlignment(int v)
	{
		alignment = v;
	}
	
	public int getSize()
	{
		return size;
	}
		
	public void setSize(int v)
	{
		size = v;
	}
	
	public int getMaxLines()
	{
		return max_lines;
	}
		
	public void setMaxLines(int v)
	{
		max_lines = v;
	}

	public boolean isMonospace()
	{
		return monospace;
	}
		
	public void setMonospace(boolean v)
	{
		monospace = v;
	}
	
	public void useDefaultFont(boolean v)
	{
		default_font = v;
	}
	
	public boolean shouldUseDefaultFont()
	{
		return default_font;
	}
}
