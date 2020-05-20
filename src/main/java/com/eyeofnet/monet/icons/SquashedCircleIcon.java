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

public class SquashedCircleIcon extends BaseIcon {


    public SquashedCircleIcon()
    {
    	fill_color = Color.WHITE;
    	height /= 2;
    }
    
    public void setColor(Color c)
    {
    	fill_color = c;
    }

    public void paintIcon(Component c, Graphics g, int x, int y) {
        Graphics2D g2d = (Graphics2D) g.create();

        g2d.setColor(fill_color);
        g2d.fillOval(x,y,width,height);

        g2d.setColor(Color.BLACK);
        g2d.drawOval(x,y,width,height);

        g2d.dispose();
    }

}
