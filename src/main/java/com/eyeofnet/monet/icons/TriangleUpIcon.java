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

package com.eyeofnet.monet.icons;

import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Polygon;

public class TriangleUpIcon extends BaseIcon {
	
    public TriangleUpIcon()
    {
    	fill_color = Color.WHITE;
    }
    
    public void setColor(Color c)
    {
    	fill_color = c;
    }

    public void paintIcon(Component c, Graphics g, int x, int y) {
        Graphics2D g2d = (Graphics2D) g.create();

        g2d.setColor(fill_color);

        int half_width = width/2;

        Polygon p = new Polygon();
        p.addPoint(x+half_width,y);
        p.addPoint(x+width,y+height);
        p.addPoint(x,y+height);
        p.addPoint(x+half_width,y);

        g2d.fillPolygon(p);
        
        g2d.setColor(Color.BLACK);
        g2d.drawPolygon(p);

        g2d.dispose();
    }

}
