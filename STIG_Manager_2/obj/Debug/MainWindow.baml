   M S B A M L   `   `   `  ����I  ESTIG_Manager_2, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null/clr-namespace:STIG_Manager_2STIG_Manager_2  5   	       STIG_Manager_2.MainWindow   5   	   W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   .localclr-namespace:STIG_Manager_2     5   	   -   5        $��STIG_Manager��5   	     � Title$  STIG Manager��5	   	   $	��700��6   $
��1200��6+    � WindowStartupLocation$ CenterScreen=�6W   .��5
      � -   5         �Name$ MainGrid��5
      ��5   
   �� 5       �� EndPoint$ 0.5,1&�6"    �� 
StartPoint$ 0.5,0&�63    �� RelativeTransform 5      V� 5      .~�5      ��  �� CenterY$	 0.5Q�6)    �� CenterX$	 0.5Q�67   �� 5       �� CenterY$	 0.5Q�6(   	 �� CenterX$		 0.5Q�66   �� 5      
 �� Angle$
 90Q�6*    �� CenterY$	 0.5Q�65    �� CenterX$	 0.5Q�6C   T� 5      5      .��5      �  � Color$ 	#FFEDF2FF��6    � Offset$ 0.107Q�61   � 5      $ 	#FFDDFFD5��6   $ 0.465Q�61   � 5      $ 	#FFEDF2FF��6   $ 0.905Q�61   5       � ColumnDefinitions 5   
   �� 5      $
��1.1* �6   �� 5      $
��Auto �6   �� 5      $��4* �6   �� 5      $
��Auto �6   �� 5      $��1* �6   .+�5!   
   �� $��0��6   
�������$��1q�69    �� Padding$ 10q�6M   ._�5"      �  � RowDefinitions 5#      �� 5$      $��* �6$   .+�5'      �� -   5         ��Name$ 	txtSearch��5'      $��10q�6-   $��	Search...��69   $	��Top=�6�   .��6�    � ToolTip 5(      �� 5)      $	��300��6!   ._�5*      �� .+�5+   "   �� $
��Bold"�6(   $��Search��6:   �� 5,   "   $��WrapWithOverflow=�6,   $d��^The search textbox will search through the STIGs and find any matching text within that STIG. ��6L   $��10q�6�   5-      5.      .��5/   '   50      ]� 51      $��
10,30,10,0q�6   ��.  $	��Top=�6F   .+�52      �� $��Showing��6    �� 53      $	��5,0q�6`   ��6    �� *Items.Count+ �� ElementName$ dataGrid�� �� Mode$ OneWay=�6`   �� 54      -   5         ��Name$ chkbxShowAll��54      $��Show All��65   $��0,0,10,0q�6H   $��Right=�6Z   $��Center=�6q    55      �� 56      $	��300��6%   ._�57   "   �� .+�58   &   �� $
��Bold"�6,   $��Show All��6>   �� 59   &   $��WrapWithOverflow=�60   $_��YThe show all checkbox when checked will remove the default filter (Hide automated STIGs).��6P   $��10q�6�   5:   #   5;      5=      5>      &   System.Windows.Controls.DataGrid  5?      -   5          Name$ dataGrid��5?      $��10,50,10,10q�6-      CanUserAddRows .     CanUserDeleteRows .     
IsReadOnly .    AutoGenerateColumns .     SelectionUnit$ FullRow=�5A   7   !   EnableColumnVirtualization . ��5?   B   �� *Vulns+   Columns 5B      0  *System.Windows.Controls.DataGridTextColumn  5C      ,  &System.Windows.Controls.DataGridColumn   Header$ ID��6-       
IsReadOnly  . !   SortDirection$! 	AscendingX�6b   1  +System.Windows.Controls.DataGridBoundColumn"   Binding" 69   �� *ID+6b     5D      $ Status��6-   #   Width5  /System.Windows.Controls.DataGridLengthConverter$# * 6\     . " 6=   �� *
DispStatus+6f   $   RowStyle$ 5F      �� 5G      % �� 
TargetType)  #System.Windows.Controls.DataGridRow"%  6    & �� Triggers& 5H      �� 5I   "   ' �� Binding' 6.   �� *
DispStatus+( �� Value( Open6M   .a�5J   &   �� ) �� Property) � ��* �� Value
* �����6C   5K   #   �� 5L   "   ' 6.   �� *
DispStatus+( Not A Finding6M   .a�5M   &   �� ) � ��
* ����6C   5N   #   �� 5O   "   ' 6.   �� *
DispStatus+( Not Applicable6M   .a�5P   &   �� ) � ��
* ��ح�6C   5Q   #   �� 5R   "   ' 6.   �� *IsPassWithCondition+( True6V   .a�5S   &   �� ) � ��* �	#FFFBF3496C   5T   #   5V      5X      5Y      5Z      �� 5[   
   $��1��6   $��0��6'   $��Center=�64   $��Stretch=�6Q   
�������+ �� ShowsPreview+ . $��5��6�   �� 5\   
   $��2��6   
�������$��1q�69   $ 10q�6M   ._�5]      �  5^      �� 5_      $
��1.8* �6$   �� 5`      $
��Auto �6$   �� 5a      $
��1.8* �6$   �� 5b      $
��Auto �6$   �� 5c      $��1* �6$   �� 5d      $
��Auto �6$   �� 5e      $
��0.8* �6$   .+�5g      � $
��10,0q�6   $
��Left=�6*   $��0��6E   .+�5h      �� $��PowerShell Script:��6    $
��Bold"�6:   $
��Left=�6L   $��0,0,10,0q�6g   $��Bottom=�6y   �� 5i      $��Version��6    $
��10,0q�6/   $��Center=�6=   $
��Bold"�6X   �� 5j      -   5        , ��Name$, cbPowerShellVersion��5j      $��Center=�6<   $	��0,3q�6W   - �� 
IsReadOnly- . ��6v   �� *SelectedItem.Versions+$ dataGrid��. �� SelectedItem. 6�   �� *SelectedItem.Current_Version+$ dataGrid��/ �� FallbackValue$/ 0��$ TwoWay=�0 �� UpdateSourceTrigger$0 	LostFocus=� 5k      �� 5l      $	��300��6%   ._�5m   "   �� .+�5n   &   �� $
��Bold"�6,   $��Version��6>   �� 5o   &   $��WrapWithOverflow=�60   $����The version dropdown will create different versions for each change you make on a script. This allows you to make changes to the script without worrying about losing your previous working version.  The version will increment when the script textbox loses focus.��6P   $��10q�5p   C   5q   #   5r      5t      �� 5u      -   5        $ toggleManualOnly��5u      $��Is Manual Only��69   $��	20,2,10,2q�5v   �   $��Center=�6�   $��Center=�6�   1 d� 	IsChecked1 6   �� *SelectedItem.IsManualOnly+$ dataGrid��$/ False��$ TwoWay=�$0 PropertyChanged=� 5w      �� 5x      $	��300��6%   ._�5y   "   �� .+�5z   &   �� $
��Bold"�6,   $��Is Manual Only��6>   �� 5{   &   $��WrapWithOverflow=�60   $����The is manual only checkbox is a way for you to specify what kind of check you want to perform.  For example if you don't want to write a                                                 script for this STIG and just want to verify this STIG manually, check this checkbox and it will be skipped when running the scripts.  This checkbox will persist when you run across                                                 different checklist files.��6P   $��10q�5}   L   5~   #   5      5�      �� 5�      -   5        2 ��Name$2 btnParseScript��5�      $��Parse Script��65   $
��10,1q�6L   $
��10,4q�6[    5�      �� 5�      $	��300��6%   ._�5�   "   �� .+�5�   &   �� $
��Bold"�6,   $��Parse Script��6>   �� 5�   &   $��WrapWithOverflow=�60   $����The parse script button will search the existing check content of the selected STIG and try to parse a powershell script from it.��6P   $��10q�6�   5�   #   5�      5�      �� 5�      -	   5        $2 btnCleanScripts��5�      $��Clean Up Scripts��66   $
��10,1q�6Q   $
��10,4q�6`    5�      �� 5�      $	��300��6%   ._�5�   "   �� .+�5�   &   �� $
��Bold"�6,   $��Clean Up Scripts��6>   �� 5�   &   $��WrapWithOverflow=�60   $����The clean up scripts button will remove all older versions of the current script.    Once this button is clicked, it will ask you if you want to remove all versions besides the highest version.  If you choose yes,   the versions will reset to 1 and display the current version.��6P   $��10q�5�   A   5�   #   5�      5�      5�      �� 5�      -
   5        $ txtPowerShell��5�   O   $��0��6   $��5,3,5,3q�6'   $��10,30,10,10q�6f   3 �� AcceptsReturn3 . 4 �� 
AcceptsTab4 . $	��140��5�   <   "5 �� VerticalScrollBarVisibility$5 Visible=�6L   6 �� TextWrapping$6 WrapWithOverflow=�5�      7 �� 	UndoLimit$	7 500��6�   ��6:   �� *SelectedItem.Current_Script+$ dataGrid��$ TwoWay=�$0 	LostFocus=�6�   � 5�      -   5        8 �Name$8 psPopUp��5�      $	��298��6)   $	��150��65   9 � PlacementTarget9 6E   �� $ txtPowerShell��.��5�      �� 
���   �$��1q�61   $	��Top=�6E   ._�5�      �� $
��Auto=�6'   
�������.��5�      �� -   5        : ��Name$: stkAutoComplete��5�   )   5�      5�      5�      �� 5�      $��1��6   $��Center=�6,   $��Stretch=�6G   
�������+ . $��3��6�   �� 5�      $��2��6   ���	#FFABADB3$��1q�6>   $��10q�6R   ._�5�      �� $��Visible=�6#   $��5,0,0,0q�6I   .��5�      �� .+�5�      �� $��Group Title:��6(   $
��Bold"�6<   $��0,5,10,0q�6N   �� 5�      -   5        ; ��Name$; txbGroupTitle��5�   (   $��WrapWithOverflow=�6?   $��
15,0,10,10q�6_   ��6s   �� *SelectedItem.GroupTitle+$ dataGrid���� 5�      $��Rule Title:��6(   $
��Bold"�6;   $��0,5,10,0q�6M   �� 5�      -   5        $; txbRuleTitle��5�   (   $��WrapWithOverflow=�6>   $��	15,0,10,0q�6^   ��6q   �� *SelectedItem.RuleTitle+$ dataGrid���� 5�      $��Discussion:��6(   $
��Bold"�6;   $��0,5,10,0q�6M   �� 5�      -   5        $; txbDiscussion��5�   (   $��WrapWithOverflow=�6?   $��
15,0,10,10q�6_   ��6s   �� *SelectedItem.Discussion+$ dataGrid���� 5�      $��Check Text:��6(   $
��Bold"�6;   $��0,5,10,0q�6M   �� 5�      -   5        $; txbCheckText��5�   (   $��WrapWithOverflow=�6>   $��
15,0,10,10q�6^   ��6r   �� *SelectedItem.CheckContent+$ dataGrid���� 5�      $��	Fix Text:��6(   $
��Bold"�69   $��0,5,10,0q�6K   �� 5�      -   5        $; 
txbFixText��5�   (   $��WrapWithOverflow=�6<   $��
15,0,10,10q�6\   ��6p   �� *SelectedItem.FixText+$ dataGrid��5�      5�      5�      �� 5�      $��3��6   $��Center=�6,   $��Stretch=�6G   
�������+ . $��3��6�   � 5�      $��4��6   .+�5�      �� $��Finding Details:��6    $
��Bold"�68   $��	10,5,10,0q�6J   $
��Left=�6]   $��Bottom=�6x   �� 5�      $��Status:��6    $
��Bold"�6/   $��20,5,5,0q�6A   �� 5�      -   5        $, cbStatus��5�   +   $	��140��6   $��5,3,0,3q�6=   ��6N   �� *Vuln.Statuses+< �� SelectedValue< 5�      �� *SelectedItem.DispStatus+$ dataGrid��$ TwoWay=�$0 	LostFocus=��� 5�      $
��Bold"�6W   $
��20,3q�6i   $
��10,3q�6w   $��Center=�6�   $��Center=�6�   = � UseLayoutRounding= .  > � DataContext> 6   �� *SelectedItem+$ dataGrid����5�      �� 5�      "% ��6$   .�5�   "   �� ) � ��
* ���� 6?   �� 5�   "   ) � ��$* 
(Severity)��6<   & 5�   "   �� 5�   &   ' 62   �� *
Severity+( high6O   .a�5�   *   �� ) � ��
* �r���6G   �� 5�   *   ) � ��$* CAT I��6D   5�   '   �� 5�   &   ' 62   �� *
Severity+
( medium6O   .a�5�   *   �� ) � ��* �	#FFF4FA726G   �� 5�   *   ) � ��$* CAT II��6D   5�   '   �� 5�   &   ' 62   �� *
Severity+( low6O   .a�5�   *   �� ) � ��* �	#FF7EFA726G   �� 5�   *   ) � ��$* CAT III��6D   5�   '   5�      5�      5�      �� 5�      -   5        $ txtFindingDetails��5�   '   $��4��6   $��10,30,10,10q�6�   3 . 4 . $6 WrapWithOverflow=�6�   ��6B   �� *SelectedItem.FindingDetails+$ dataGrid��$ TwoWay=�$0 	LostFocus=�6�   �� 5�      $��5��6   $��Center=�6,   $��Stretch=�6G   
�������+ . $��3��6�   �� 5�      $��6��6   $��Comments��6)   $
��Bold"�69   $��10q�6K   �� 5�      -   5        $ txtComments��5�   '   $��6��6   $��10,30,10,10q�6�   3 . 4 . $6 WrapWithOverflow=�6�   ��6<   �� *SelectedItem.Comments+$ dataGrid��$ TwoWay=�$0 	LostFocus=�6�   5�      5�      �� 5�   
   $��3��6   $��0��6'   $��Center=�64   $��Stretch=�6Q   
�������+ . $��5��6�   �� 5�   
   $��4��6   
�������$��1q�69   $ 10q�6M   ._�5�      �� .+�5�      �� $��PowerShell:��6   $	��5,0q�6/   �� 5�      -   5        $2 btnRun��5�      $
��10,1q�6)   $��	10,5,10,0q�68   $��Test Script��6K    5�      �� 5�      $	��300��6!   ._�5�      �� .+�5�   "   �� $
��Bold"�6(   $��Test Script��6:   �� 5�   "   $��WrapWithOverflow=�6,   $|��vThe test script button will run the currently selected script against the machine you are running this application on.��6L   $��10q�6�   5�      5�      5�      � 5�      -   5        ? �Name$? progressBar_Run��5�      @ � IsIndeterminate@ . $��	10,0,10,5q�6N   $��5��6a   $y�Hidden=�6l   �� 5�      -   5        $2 	btnRunAll��5�      $
��10,1q�6,   $��	10,5,10,0q�6;   $��Run All��6N    5�      �� 5�      $	��300��6!   ._�5�      �� .+�5�   "   �� $
��Bold"�6(   $��Run All��6:   �� 5�   "   $��WrapWithOverflow=�6,   $����The run all button will interate through all the manual STIGs and run the powershell script for that STIG on the local machine.  Once they have completed running, the results will be stored in the STIG's findings.��6L   $��10q�6)  5�      5�      5�      � 5�      -   5        $? progressBar_RunAll��5�      @ . $��	10,0,10,5q�6Q   $��5��6d   $y�Hidden=�6o   �� 5�      -   5        $2 btnRunRemote��5�      $
��10,1q�6/   $��
10,5,10,10q�6>   $��
Run Remote��6R    5�      �� 5�      $	��300��6!   ._�5�      �� .+�5�   "   �� $
��Bold"�6(   $��
Run Remote��6:   �� 5�   "   $��WrapWithOverflow=�6,   $����The run remote button will display the remote computers window, where you can run all the scripts against a remote machine.    The results will be stored in a copy of the current checklist with a small identifier appended to the filename.��6L   $��10q�5�   s   5�      5�      5�      �� 5      -   5        $2 btnSearchRegedit��5      $
��10,1q�63   $��
10,5,10,10q�6B   $��Search For Key��6V   {�6�   �� *%#SelectedItem.IsContainRegistryValue+$ dataGrid��$/ False���� 5     -   5        $2 btnFunctions��5     $
��10,1q�6/   $��
10,5,10,10q�6>   $��	Functions��6R    5     �� 5     $	��300��6!   ._�5     �� .+�5  "   �� $
��Bold"�6(   $��	Functions��6:   �� 5  "   $��WrapWithOverflow=�6,   $���}The functions button opens the functions window, where you are able to add/modify functions that you can use in your scripts.��6L   $��10q�6�   5     5     5
     �� 5     -   5        $2 btnLoadScripts��5     $��10,1 q�61   $��
10,5,10,10q�6A   $��Load Scripts��6U    5     �� 5     $	��300��6!   ._�5     �� .+�5  "   �� $
��Bold"�6(   $��Load Scripts��6:   �� 5  "   $��WrapWithOverflow=�6,   $x��rThe load scripts button will accept a .ps1/.txt file and try to parse it to populate the STIGs with those scripts.��6L   $��10q�6�   5     5     5     �� 5     $
��10,5q�6   $��3��6*   �� 5     $��
Checklist:��6   $	��5,0q�6.   �� 5     $
��10,0q�6"   A �� BulletA 5     A� 5     $��2��6"   $��4��6-   
���   �67   ._�5     �� -   5        $; txbCName��5      $��WrapWithOverflow=�6q   $	��3,0q�6�   ��62   �� *Short_Title+$/ Title��$ OneWay=�6�   5     �� 5     $
��10,0q�6"   A 5     A� 5      $��2��6"   $��4��6-   
���   �67   ._�5"     �� -   5        $; txbCRelease��5"      $��WrapWithOverflow=�6{   $	��3,0q�6�   ��65   �� *ReleaseInfo+$/ Release Info��$ OneWay=�6�   5#     �� 5$     $
��10,0q�6"   A 5%     A� 5&     $��2��6"   $��4��6-   
���   �67   ._�5(     �� -   5        $; txbCVersion��5(      $��WrapWithOverflow=�6r   $	��3,0q�6�   ��65   �� *	Version+$/ Version��$ OneWay=�6�   5)     �� 5*     -    5        $2 btnChecklist��5*     $
��10,1q�6/   $��10q�6>   $��Load Checklist��6J   6c   �� 5+     -!   5        $, cbRemoteNames��5+     $
��10,1q�62   $��	10,5,10,0q�6A    5,     �� 5-     $	��250��6$   $����Click to select a remote computer name. Then click the Save New button to save a copy of the current checkfile with the remote computer name.��60   $��WrapWithOverflow=�6�   $��10q�6�   5/     �� 50     -"   5        $2 btnSaveNewChecklist��50     $
��10,1q�66   $��10q�6E   $��Save New��6Q    51     �� 52     $	��300��6!   ._�53     �� .+�54  "   �� $
��Bold"�6(   $��Save New��6:   �� 55  "   $��WrapWithOverflow=�6,   $u��oThe save new button takes the currently loaded checklist and creates a copy of it wherever you want to save it.��6L   $��10q�6�   56     57     59     �� 5:     $
��10,5q�6   $��3��6*   �� 5;     $��
Benchmark:��6   $	��5,0q�6.   �� 5<     $
��10,0q�6"   A 5=     A� 5>     $��2��6"   $��4��6-   
���   �67   ._�5@     �� -#   5        $; txbBName��5@      $��WrapWithOverflow=�6q   $	��3,0q�6�   ��62   �� *Short_Title+$/ Title��$ OneWay=�6�   5A     �� 5B     $
��10,0q�6"   A 5C     A� 5D     $��2��6"   $��4��6-   
���   �67   ._�5F     �� -$   5        $; txbBRelease��5F      $��WrapWithOverflow=�6w   $	��3,0q�6�   ��65   �� *	Release+$/ Release Info��$ OneWay=�6�   5G     �� 5H     $
��10,0q�6"   A 5I     A� 5J     $��2��6"   $��4��6-   
���   �67   ._�5L     �� -%   5        $; txbBVersion��5L      $��WrapWithOverflow=�6r   $	��3,0q�6�   ��65   �� *	Version+$/ Version��$ OneWay=�6�   5M     �� 5N     -&   5        $2 btnBenchmark��5N     $
��10,1q�6/   $��10q�6>   $��Load Benchmark��6J   6c   �� 5O     -'   5        $2 btnClearBenchmark��5O     $
��10,1q�64   $��
10,5,10,10q�6C   $��Clear Benchmark��6W   6q   �� 5P     $
��10,5q�6   $��3��6*   �� 5Q     $��	Settings:��6   $	��5,0q�6-   �� 5R     -(   5        $2 btnSave��5R     $
��10,1q�6*   $��10q�69   $
��Save��6E   ���	#FF78FF596g   5S     5T     5U     5W     