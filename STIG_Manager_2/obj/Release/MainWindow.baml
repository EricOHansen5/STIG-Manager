   M S B A M L   `   `   `  ���� I  ESTIG_Manager_2, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null/clr-namespace:STIG_Manager_2STIG_Manager_2      STIG_Manager_2.MainWindow   W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     @d2http://schemas.microsoft.com/expression/blend/2008     Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     .localclr-namespace:STIG_Manager_2     -   $��STIG_Manager��  � Title$  STIG Manager��$	��700��$
��1200�� � WindowStartupLocation$ CenterScreen=�.��� -    �Name$ MainGrid������  �� EndPoint$ 0.5,1&� �� 
StartPoint$ 0.5,0&� �� RelativeTransform V� .~���  �� CenterY$	 0.5Q� �� CenterX$	 0.5Q���  �� CenterY$	 0.5Q�	 �� CenterX$		 0.5Q��� 
 �� Angle$
 90Q� �� CenterY$	 0.5Q� �� CenterX$	 0.5Q�T� .���  � Color$ 	#FFEDF2FF�� � Offset$ 0.107Q�� $ 	#FFDDFFD5��$ 0.465Q�� $ 	#FFEDF2FF��$ 0.905Q� � ColumnDefinitions �� $
��1.1* ��� $
��Auto ��� $��4* ��� $
��Auto ��� $��1* �.+��� $��0��
�������$��1q� �� Padding$ 10q�._��  � RowDefinitions �� $��* �.+��� -    ��Name$ 	txtSearch��$��10q�$��	Search...��$	��Top=�.�� � ToolTip �� $	��300��._��� .+��� $
��Bold"�$��Search���� $��WrapWithOverflow=�$d��^The search textbox will search through the STIGs and find any matching text within that STIG. ��$��10q�.��]� $��
10,30,10,0q���.  $	��Top=�.+��� $��Showing���� $	��5,0q����� *Items.Count+ �� ElementName$ dataGrid�� �� Mode$ OneWay=��� -    ��Name$ chkbxShowAll��$��Show All��$��0,0,10,0q�$��Right=�$��Center=� �� $	��300��._��� .+��� $
��Bold"�$��Show All���� $��WrapWithOverflow=�$_��YThe show all checkbox when checked will remove the default filter (Hide automated STIGs).��$��10q�&   System.Windows.Controls.DataGrid  -     Name$ dataGrid��$��10,50,10,10q�   CanUserAddRows .     CanUserDeleteRows .     
IsReadOnly .    AutoGenerateColumns .     SelectionUnit$ FullRow=�!   EnableColumnVirtualization . ���� *Vulns+   Columns 0  *System.Windows.Controls.DataGridTextColumn  ,  &System.Windows.Controls.DataGridColumn   Header$ ID��    
IsReadOnly  . !   SortDirection$! 	AscendingX�1  +System.Windows.Controls.DataGridBoundColumn"   Binding" �� *ID+  $ Status��#   Width5  /System.Windows.Controls.DataGridLengthConverter$# *   . " �� *
DispStatus+$   RowStyle$ �� % �� 
TargetType)  #System.Windows.Controls.DataGridRow"%  & �� Triggers& �� ' �� Binding' �� *
DispStatus+( �� Value( Open.a��� ) �� Property) � ��* �� Value
* ������� ' �� *
DispStatus+( Not A Finding.a��� ) � ��
* ������ ' �� *
DispStatus+( Not Applicable.a��� ) � ��
* ��ح��� ' �� *IsPassWithCondition+( True.a��� ) � ��* �	#FFFBF349�� $��1��$��0��$��Center=�$��Stretch=�
�������+ �� ShowsPreview+ . $��5���� $��2��
�������$��1q�$ 10q�._��  �� $
��1.8* ��� $
��Auto ��� $
��1.8* ��� $
��Auto ��� $��1* ��� $
��Auto ��� $
��0.8* �.+�� $
��10,0q�$
��Left=�$��0��.+��� $��PowerShell Script:��$
��Bold"�$
��Left=�$��0,0,10,0q�$��Bottom=��� $��Version��$
��10,0q�$��Center=�$
��Bold"��� -   , ��Name$, cbPowerShellVersion��$��Center=�$	��0,3q�- �� 
IsReadOnly- . ���� *SelectedItem.Versions+$ dataGrid��. �� SelectedItem. �� *SelectedItem.Current_Version+$ dataGrid��/ �� FallbackValue$/ 0��$ TwoWay=�0 �� UpdateSourceTrigger$0 	LostFocus=� �� $	��300��._��� .+��� $
��Bold"�$��Version���� $��WrapWithOverflow=�$����The version dropdown will create different versions for each change you make on a script. This allows you to make changes to the script without worrying about losing your previous working version.  The version will increment when the script textbox loses focus.��$��10q��� -   $ toggleManualOnly��$��Is Manual Only��$��	20,2,10,2q�$��Center=�$��Center=�1 d� 	IsChecked1 �� *SelectedItem.IsManualOnly+$ dataGrid��$/ False��$ TwoWay=�$0 PropertyChanged=� �� $	��300��._��� .+��� $
��Bold"�$��Is Manual Only���� $��WrapWithOverflow=�$����The is manual only checkbox is a way for you to specify what kind of check you want to perform.  For example if you don't want to write a                                                 script for this STIG and just want to verify this STIG manually, check this checkbox and it will be skipped when running the scripts.  This checkbox will persist when you run across                                                 different checklist files.��$��10q��� -   2 ��Name$2 btnParseScript��$��Parse Script��$
��10,1q�$
��10,4q� �� $	��300��._��� .+��� $
��Bold"�$��Parse Script���� $��WrapWithOverflow=�$����The parse script button will search the existing check content of the selected STIG and try to parse a powershell script from it.��$��10q��� -	   $2 btnCleanScripts��$��Clean Up Scripts��$
��10,1q�$
��10,4q� �� $	��300��._��� .+��� $
��Bold"�$��Clean Up Scripts���� $��WrapWithOverflow=�$����The clean up scripts button will remove all older versions of the current script.    Once this button is clicked, it will ask you if you want to remove all versions besides the highest version.  If you choose yes,   the versions will reset to 1 and display the current version.��$��10q��� -
   $ txtPowerShell��$��0��$��5,3,5,3q�$��10,30,10,10q�3 �� AcceptsReturn3 . 4 �� 
AcceptsTab4 . $	��140��"5 �� VerticalScrollBarVisibility$5 Visible=�6 �� TextWrapping$6 WrapWithOverflow=�7 �� 	UndoLimit$	7 500������ *SelectedItem.Current_Script+$ dataGrid��$ TwoWay=�$0 	LostFocus=�� -   8 �Name$8 psPopUp��$	��298��$	��150��9 � PlacementTarget9 �� $ txtPowerShell��.���� 
���   �$��1q�$	��Top=�._��� $
��Auto=�
�������.���� -   : ��Name$: stkAutoComplete���� $��1��$��Center=�$��Stretch=�
�������+ . $��3���� $��2�����	#FFABADB3$��1q�$��10q�._��� $��Visible=�$��5,0,0,0q�.���� .+��� $��Group Title:��$
��Bold"�$��0,5,10,0q��� -   ; ��Name$; txbGroupTitle��$��WrapWithOverflow=�$��
15,0,10,10q����� *SelectedItem.GroupTitle+$ dataGrid���� $��Rule Title:��$
��Bold"�$��0,5,10,0q��� -   $; txbRuleTitle��$��WrapWithOverflow=�$��	15,0,10,0q����� *SelectedItem.RuleTitle+$ dataGrid���� $��Discussion:��$
��Bold"�$��0,5,10,0q��� -   $; txbDiscussion��$��WrapWithOverflow=�$��
15,0,10,10q����� *SelectedItem.Discussion+$ dataGrid���� $��Check Text:��$
��Bold"�$��0,5,10,0q��� -   $; txbCheckText��$��WrapWithOverflow=�$��
15,0,10,10q����� *SelectedItem.CheckContent+$ dataGrid���� $��	Fix Text:��$
��Bold"�$��0,5,10,0q��� -   $; 
txbFixText��$��WrapWithOverflow=�$��
15,0,10,10q����� *SelectedItem.FixText+$ dataGrid���� $��3��$��Center=�$��Stretch=�
�������+ . $��3��� $��4��.+��� $��Finding Details:��$
��Bold"�$��	10,5,10,0q�$
��Left=�$��Bottom=��� $��Status:��$
��Bold"�$��20,5,5,0q��� -   $, cbStatus��$	��140��$��5,3,0,3q����� *Vuln.Statuses+< �� SelectedValue< �� *SelectedItem.DispStatus+$ dataGrid��$ TwoWay=�$0 	LostFocus=��� $
��Bold"�$
��20,3q�$
��10,3q�$��Center=�$��Center=�= � UseLayoutRounding= .  > � DataContext> �� *SelectedItem+$ dataGrid������ "% ��.��� ) � ��
* ���� �� ) � ��$* 
(Severity)��& �� ' �� *
Severity+( high.a��� ) � ��
* �r����� ) � ��$* CAT I���� ' �� *
Severity+
( medium.a��� ) � ��* �	#FFF4FA72�� ) � ��$* CAT II���� ' �� *
Severity+( low.a��� ) � ��* �	#FF7EFA72�� ) � ��$* CAT III���� -   $ txtFindingDetails��$��4��$��10,30,10,10q�3 . 4 . $6 WrapWithOverflow=����� *SelectedItem.FindingDetails+$ dataGrid��$ TwoWay=�$0 	LostFocus=��� $��5��$��Center=�$��Stretch=�
�������+ . $��3���� $��6��$��Comments��$
��Bold"�$��10q��� -   $ txtComments��$��6��$��10,30,10,10q�3 . 4 . $6 WrapWithOverflow=����� *SelectedItem.Comments+$ dataGrid��$ TwoWay=�$0 	LostFocus=��� $��3��$��0��$��Center=�$��Stretch=�
�������+ . $��5���� $��4��
�������$��1q�$ 10q�._��� .+��� $��PowerShell:��$	��5,0q��� -   $2 btnRun��$
��10,1q�$��	10,5,10,0q�$��Test Script�� �� $	��300��._��� .+��� $
��Bold"�$��Test Script���� $��WrapWithOverflow=�$|��vThe test script button will run the currently selected script against the machine you are running this application on.��$��10q�� -   ? �Name$? progressBar_Run��@ � IsIndeterminate@ . $��	10,0,10,5q�$��5��$y�Hidden=��� -   $2 	btnRunAll��$
��10,1q�$��	10,5,10,0q�$��Run All�� �� $	��300��._��� .+��� $
��Bold"�$��Run All���� $��WrapWithOverflow=�$����The run all button will interate through all the manual STIGs and run the powershell script for that STIG on the local machine.  Once they have completed running, the results will be stored in the STIG's findings.��$��10q�� -   $? progressBar_RunAll��@ . $��	10,0,10,5q�$��5��$y�Hidden=��� -   $2 btnRunRemote��$
��10,1q�$��
10,5,10,10q�$��
Run Remote�� �� $	��300��._��� .+��� $
��Bold"�$��
Run Remote���� $��WrapWithOverflow=�$����The run remote button will display the remote computers window, where you can run all the scripts against a remote machine.    The results will be stored in a copy of the current checklist with a small identifier appended to the filename.��$��10q��� -   $2 btnSearchRegedit��$
��10,1q�$��
10,5,10,10q�$��Search For Key��{��� *%#SelectedItem.IsContainRegistryValue+$ dataGrid��$/ False���� -   $2 btnFunctions��$
��10,1q�$��
10,5,10,10q�$��	Functions�� �� $	��300��._��� .+��� $
��Bold"�$��	Functions���� $��WrapWithOverflow=�$���}The functions button opens the functions window, where you are able to add/modify functions that you can use in your scripts.��$��10q��� -   $2 btnLoadScripts��$��10,1 q�$��
10,5,10,10q�$��Load Scripts�� �� $	��300��._��� .+��� $
��Bold"�$��Load Scripts���� $��WrapWithOverflow=�$x��rThe load scripts button will accept a .ps1/.txt file and try to parse it to populate the STIGs with those scripts.��$��10q��� $
��10,5q�$��3���� $��
Checklist:��$	��5,0q��� $
��10,0q�A �� BulletA A� $��2��$��4��
���   �._��� -   $; txbCName��$��WrapWithOverflow=�$	��3,0q����� *Short_Title+$/ Title��$ OneWay=��� $
��10,0q�A A� $��2��$��4��
���   �._��� -   $; txbCRelease��$��WrapWithOverflow=�$	��3,0q����� *ReleaseInfo+$/ Release Info��$ OneWay=��� $
��10,0q�A A� $��2��$��4��
���   �._��� -   $; txbCVersion��$��WrapWithOverflow=�$	��3,0q����� *	Version+$/ Version��$ OneWay=��� -    $2 btnChecklist��$
��10,1q�$��10q�$��Load Checklist���� -!   $, cbRemoteNames��$
��10,1q�$��	10,5,10,0q� �� $	��250��$����Click to select a remote computer name. Then click the Save New button to save a copy of the current checkfile with the remote computer name.��$��WrapWithOverflow=�$��10q��� -"   $2 btnSaveNewChecklist��$
��10,1q�$��10q�$��Save New�� �� $	��300��._��� .+��� $
��Bold"�$��Save New���� $��WrapWithOverflow=�$u��oThe save new button takes the currently loaded checklist and creates a copy of it wherever you want to save it.��$��10q��� $
��10,5q�$��3���� $��
Benchmark:��$	��5,0q��� $
��10,0q�A A� $��2��$��4��
���   �._��� -#   $; txbBName��$��WrapWithOverflow=�$	��3,0q����� *Short_Title+$/ Title��$ OneWay=��� $
��10,0q�A A� $��2��$��4��
���   �._��� -$   $; txbBRelease��$��WrapWithOverflow=�$	��3,0q����� *	Release+$/ Release Info��$ OneWay=��� $
��10,0q�A A� $��2��$��4��
���   �._��� -%   $; txbBVersion��$��WrapWithOverflow=�$	��3,0q����� *	Version+$/ Version��$ OneWay=��� -&   $2 btnBenchmark��$
��10,1q�$��10q�$��Load Benchmark���� -'   $2 btnClearBenchmark��$
��10,1q�$��
10,5,10,10q�$��Clear Benchmark���� $
��10,5q�$��3���� $��	Settings:��$	��5,0q��� -(   $2 btnSave��$
��10,1q�$��10q�$
��Save�����	#FF78FF59