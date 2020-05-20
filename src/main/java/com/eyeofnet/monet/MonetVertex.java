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
import java.util.ArrayList;

import javax.swing.Icon;

import ghidra.program.model.graph.GraphVertex;

import com.eyeofnet.monet.icons.*;


public class MonetVertex implements GraphVertex {

	private String gid;
	private String name;
	private String label_attr_name = null;
	private ArrayList<NameValuePair> attributes;

	
	public MonetVertex(String id)
	{
		gid = id;
		attributes = new ArrayList<NameValuePair>();
	}
	
    @Override
    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }


    @Override
    public String getID() {
        return gid;
    }
    
    @Override
    public void setAttribute(String attributeName, String value) {
        boolean found = false;
        NameValuePair nv = new NameValuePair(attributeName,value);

        for (int idx=0;idx<attributes.size();idx++) {
            if (attributes.get(idx).getName().contentEquals(attributeName)) {
                attributes.get(idx).setValue(value);
                found = true;
            }
        }
        if (false == found) {
            attributes.add(nv);
        }

    }

    @Override
    public String getAttribute(String attributeName) {
        String rv = null;
        for (NameValuePair nv : attributes ) {
            if (nv.getName().contentEquals(attributeName)) {
                rv = nv.getValue();
            }
        }
        return rv;
    }
    
    public void setLabelAttributeName(String v)
    {
    	label_attr_name = v;
    }
    
    public String toString()
    {
    	String rv = name;
    	if (null != label_attr_name) {
    		String label_attr_value = getAttribute(label_attr_name);
    		if (null != label_attr_value) {
    			rv = label_attr_value;
    		}
    	}
    	return rv;
    }
    
    public Color getColor()
    {
    	Color rv = Color.WHITE;
    	String color_name = getAttribute(COLOR_ATTRIBUTE);
    	if (null != color_name) {
    		rv = MonetPlugin.getColorFromName(color_name);
    	}
    	return rv;
    }
    
    public Icon getIcon()
    {
    	Icon rv = null;
    	String attr_name = getAttribute(ICON_ATTRIBUTE);
    	
    	if (null != attr_name) {
    		if (attr_name.contentEquals(ICON_SQUARE))
    		{
    			SquareIcon ic = new SquareIcon();
    			ic.setColor(getColor());
    			rv = ic;
    		} else if (attr_name.contentEquals(ICON_CIRCLE)) {
    			CircleIcon ic = new CircleIcon();
    			ic.setColor(getColor());
    			rv = ic;
    		} else if (attr_name.contentEquals(ICON_SQUASHED_CIRCLE)) {
    			SquashedCircleIcon ic = new SquashedCircleIcon();
    			ic.setColor(getColor());
    			rv = ic;
    		} else if (attr_name.contentEquals(ICON_TRIANGLE_DOWN)) {
    			TriangleDownIcon ic = new TriangleDownIcon();
    			ic.setColor(getColor());
    			rv = ic;    		
    		} else if (attr_name.contentEquals(ICON_TRIANGLE_UP)) {
    			TriangleUpIcon ic = new TriangleUpIcon();
    			ic.setColor(getColor());
    			rv = ic;    		
    		} else if (attr_name.contentEquals(ICON_DIAMOND)) {
    			DiamondIcon ic = new DiamondIcon();
    			ic.setColor(getColor());
    			rv = ic;    		
    		} else {
    			// Default until we find out what shape it is supposed to be
    			DiamondIcon ic = new DiamondIcon();
    			ic.setColor(getColor());
    			rv = ic;
    		}
    	} else {
    		attr_name = getAttribute(VERTEX_TYPE_ATTRIBUTE);
    		if (null != attr_name) {
    		    if (attr_name.contentEquals(VERTEX_TYPE_ENTRY)) {
    			    TriangleDownIcon ic = new TriangleDownIcon();
    			    ic.setColor(getColor());
    			    rv = ic;    		    			
    		    } else if (attr_name.contentEquals(VERTEX_TYPE_BODY)) {
    			    CircleIcon ic = new CircleIcon();
    			    ic.setColor(getColor());
    			    rv = ic;    			
    		    } else if (attr_name.contentEquals(VERTEX_TYPE_EXIT)) {
    			    TriangleUpIcon ic = new TriangleUpIcon();
    			    ic.setColor(getColor());
    			    rv = ic;    			
    		    } else if (attr_name.contentEquals(VERTEX_TYPE_SWITCH)) {
    			    DiamondIcon ic = new DiamondIcon();
    			    ic.setColor(getColor());
    			    rv = ic;
    		    } else if (attr_name.contentEquals(VERTEX_TYPE_DATA)) {
    			    SquareIcon ic = new SquareIcon();
    			    ic.setColor(getColor());
    			    rv = ic;
    		    } else if (attr_name.contentEquals(VERTEX_TYPE_BAD)) {
    			    SquashedCircleIcon ic = new SquashedCircleIcon();
    			    ic.setColor(getColor());
    			    rv = ic;
    		    }
            } else {
    		    // Default until we find out what shape it is supposed to be
    		    CircleIcon ic = new CircleIcon();
    			ic.setColor(getColor());
    			rv = ic;    			
    		}
    	}
    	return rv;
    }

    public static final String COLOR_ATTRIBUTE = "Color";
    public static final String ICON_ATTRIBUTE = "Icon";
    public static final String ICON_SQUARE = "Square";
    public static final String ICON_CIRCLE = "Circle";
    public static final String ICON_SQUASHED_CIRCLE = "SquashedCircle";
    public static final String ICON_TRIANGLE_DOWN = "TriangleDown";
    public static final String ICON_TRIANGLE_UP = "TriangleUp";
    public static final String ICON_DIAMOND = "Diamond";
    
    public static final String VERTEX_TYPE_ATTRIBUTE = "VertexType";
    public static final String VERTEX_TYPE_ENTRY = "Entry";
    public static final String VERTEX_TYPE_BODY = "Body";
    public static final String VERTEX_TYPE_EXIT = "Exit";
    public static final String VERTEX_TYPE_SWITCH = "Switch";
    public static final String VERTEX_TYPE_DATA = "Data";
    public static final String VERTEX_TYPE_BAD = "Bad";
    
}
