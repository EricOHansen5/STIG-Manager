   M S B A M L   `   `   `  ����I  ESTIG_Manager_2, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null9!clr-namespace:STIG_Manager_2.ViewSTIG_Manager_2.View  5   	   )    #STIG_Manager_2.View.FunctionsWindow   5   	   W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   3local!clr-namespace:STIG_Manager_2.View     5   	   -   5        $��Functions_Window��5   	     � Title$  FunctionsWindow��5	   	   $	��450��6!   $	��800��6.   .��5
      � -   5        $��MainGrid��5
   E   $��Stretch=�6   $��Stretch=�6)    � ColumnDefinitions 5   
   �� 5      $��3* �6   �� 5      $
��Auto �6   �� 5      $��* �6    � RowDefinitions 5   
   �� 5      $��* �6   .+�5   
   � $��0��6   $��0��6$    � Orientation$ 
Horizontal=�61   $��26��6J   $	��Top=�6V   .+�5      �� $��	Function:��6   $
��Left=�6(   $	��Top=�6C   �� 5      $
��Left=�6o   $	��Top=�6�   ��6   �� *SelectedItem.Value.Title+ �� ElementName$ lbFunctions�� �� FallbackValue$ Title��6�   5      �� 5   
   -   5         ��Name$ txtFunction��5   /   $��0��6   $��0��6"    �� AcceptsReturn .  �� 
AcceptsTab . $��10,25,10,10q�5      	 �� MinLines$	 23��6*   $��Stretch=�68   $��Stretch=�6T   "
 �� VerticalScrollBarVisibility$
 Visible=�6r   $ �� HorizontalScrollBarVisibility$
 Auto=�6�   $	��350��6�   ��5   D   �� *!SelectedItem.Value.LastFunction+$ lbFunctions��5   �   �� 5   
   $	��298��6   $	��150��6   
���   �$��1q�6>   $	��Top=�6R   $y�	Collapsed=�6j   $��
0,-170,0,0q�6�   $��Right=�6�   
�������._�5      �� $
��Auto=�6   .��5      �� -   5         ��Name$ stkAutoComplete��5      5      5      �� 5    
   $��1��6   $��0��6'   $��Center=�64   $��Stretch=�6Q   
������� �� ShowsPreview . $��5��6�   �� 5"   
   $��
10,0,10,10q�6   $��2��6)   $��0��69   .+�5#      �� $��	Functions��6   �� 5$      -   5        $	��Add��5$      $
��10,1q�6#   $��
10,0,10,10q�62   6F   �� 5%      -   5        $��Remove��5%      $
��10,1q�6&   $��
10,0,10,10q�65   6I   �� 5&      -   5        $
��Save��5&      $
��10,1q�6$   $��
10,0,10,10q�63   6G   �� 5'      -   5        $��Close��5'      $
��10,1q�6%   $��
10,0,10,10q�64   6H   5(      �� 5)   
   -	   5         ��Name$ lbFunctions��5)   /   $��2��6   $��0��6"   $��10,150,10,10q�6D   $	��230��6Z   ��5*      �� 5+      .R�5,      �� ��6    �� *Value.Title+5-      5/      50      51      