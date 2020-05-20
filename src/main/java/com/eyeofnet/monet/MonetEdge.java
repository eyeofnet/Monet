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

import java.util.ArrayList;

import ghidra.program.model.graph.GraphEdge;
import ghidra.program.model.graph.GraphVertex;

public class MonetEdge implements GraphEdge {

	private String eid;
	private GraphVertex start;
	private GraphVertex end;
	private ArrayList<NameValuePair> attributes;
	

	public MonetEdge(String id) {
		this.eid = id;
		attributes = new ArrayList<NameValuePair>();
	}

	@Override
	public String getID() {
		return eid;
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
	
	public void setEndpoints(GraphVertex start,GraphVertex end)
	{
		this.start = start;
		this.end = end;
	}
	
	public GraphVertex getStart()
	{
		return start;
	}

	public GraphVertex getEnd()
	{
		return end;
	}
	
	public String toString()
	{
		return eid;
	}

}
