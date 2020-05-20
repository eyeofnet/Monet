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

import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;

import docking.DialogComponentProvider;

public class SelectLayoutDialog extends DialogComponentProvider {
	
	
	public final static int int_FR_layout = 0;
	public final static int int_KK_layout = 1;
	public final static int int_ISOM_layout = 2;
	public final static int int_Circle_layout = 3;
	public final static int int_Spring_layout = 4;
	
	private int selected_layout_type = -1;
	private int current_layout_type = -1;
	private ButtonGroup group = new ButtonGroup();
	private JPanel main_panel;

	private final String str_FR_layout = "FR Layout";
	private final String str_KK_layout = "KK Layout";
	private final String str_ISOM_layout = "ISOM Layout";
	private final String str_Circle_layout = "Circle Layout";
	private final String str_Spring_layout = "Spring Layout";
 
	protected SelectLayoutDialog(String title,int current_layout) {
		super(title);
		
		current_layout_type = current_layout;
		setTitle(title);
		main_panel = createMainPanel();
		addWorkPanel(main_panel);
        addOKButton();
        addCancelButton();
	}

	public int getSelectedLayoutType()
	{
		return selected_layout_type;
	}

	private JPanel createMainPanel() {
		final int num_buttons = 5;
		JPanel rv = null;
		JRadioButton[] radio_buttons = new JRadioButton[num_buttons];

		int i = 0;
	 
		radio_buttons[i] = new JRadioButton(str_FR_layout,current_layout_type==i);
		radio_buttons[i++].setActionCommand(str_FR_layout);
		radio_buttons[i] = new JRadioButton(str_KK_layout,current_layout_type==i);
		radio_buttons[i++].setActionCommand(str_KK_layout);
		radio_buttons[i] = new JRadioButton(str_ISOM_layout,current_layout_type==i);
		radio_buttons[i++].setActionCommand(str_ISOM_layout);
		radio_buttons[i] = new JRadioButton(str_Circle_layout,current_layout_type==i);
		radio_buttons[i++].setActionCommand(str_Circle_layout);
		radio_buttons[i] = new JRadioButton(str_Spring_layout,current_layout_type==i);
		radio_buttons[i++].setActionCommand(str_Spring_layout);
		for (i=0;i<num_buttons;i++) {
			group.add(radio_buttons[i]);
		}

		JPanel box = new JPanel();
		JLabel label = new JLabel("Select graph layout");

		box.setLayout(new BoxLayout(box, BoxLayout.PAGE_AXIS));
		box.add(label);

		for (i = 0; i < radio_buttons.length; i++) {
			box.add(radio_buttons[i]);
		}

		rv = new JPanel(new BorderLayout());
		rv.add(box, BorderLayout.PAGE_START);

		return rv;
	}

    @Override
    protected void cancelCallback() {
        close();
    }

    @Override
    protected void okCallback() {
		String command = group.getSelection().getActionCommand();

		if (command.contentEquals(str_FR_layout)) {
			selected_layout_type = int_FR_layout;    	
		} else if (command.contentEquals(str_KK_layout)) {
       		selected_layout_type = int_KK_layout;    		     
		} else if (command.contentEquals(str_ISOM_layout)) {
       		selected_layout_type = int_ISOM_layout;    	
		} else if (command.contentEquals(str_Circle_layout)) {
       		selected_layout_type = int_Circle_layout;    	
		} else {
       		selected_layout_type = int_Spring_layout;    	
		}
        close();
    }


}


