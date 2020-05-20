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
import java.util.Iterator;

import ghidra.program.model.graph.GraphData;
import ghidra.program.model.graph.GraphEdge;
import ghidra.program.model.graph.GraphVertex;

public class MonetData implements GraphData {

	private ArrayList<MonetEdge> edges;
	private ArrayList<MonetVertex> vertices;
	
    public MonetData()
    {
    	edges = new ArrayList<MonetEdge>();
    	vertices = new ArrayList<MonetVertex>();
    }

	@Override
	public GraphVertex createVertex(String name, String vertexID) {
        MonetVertex rv = new MonetVertex(vertexID);
        rv.setName(name);
        //if (0 == vertices.size()) {
        //	rv.setAttribute("verbose", "true");
        //}
        vertices.add(rv);
        return rv;
	}

	@Override
	public GraphVertex getVertex(String vertexID) {
		MonetVertex rv = null;
		for (MonetVertex v : vertices) {
			if (v.getID().contentEquals(vertexID)) {
				rv = v;
				break;
			}
		}
		return rv;
	}

	@Override
	public GraphEdge createEdge(String vertexID, GraphVertex start, GraphVertex end) {
        MonetEdge rv = new MonetEdge(vertexID);
        rv.setEndpoints(start, end);
        edges.add(rv);
        return rv;
	}

	@Override
	public Iterator<MonetVertex> getVertices() {
		return vertices.iterator();
	}

	@Override
	public Iterator<MonetEdge> getEdges() {
		return edges.iterator();
	}
	
}
