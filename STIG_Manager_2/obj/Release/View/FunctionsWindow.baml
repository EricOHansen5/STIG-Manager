   M S B A M L   `   `   `  ���� I  ESTIG_Manager_2, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null9!clr-namespace:STIG_Manager_2.ViewSTIG_Manager_2.View  )    #STIG_Manager_2.View.FunctionsWindow   W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     @d2http://schemas.microsoft.com/expression/blend/2008     Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     3local!clr-namespace:STIG_Manager_2.View     -   $��Functions_Window��  � Title$  FunctionsWindow��$	��450��$	��800��.��� -   $��MainGrid��$��Stretch=�$��Stretch=� � ColumnDefinitions �� $��3* ��� $
��Auto ��� $��* � � RowDefinitions �� $��* �.+�� $��0��$��0�� � Orientation$ 
Horizontal=�$��26��$	��Top=�.+��� $��	Function:��$
��Left=�$	��Top=��� $
��Left=�$	��Top=����� *SelectedItem.Value.Title+ �� ElementName$ lbFunctions�� �� FallbackValue$ Title���� -    ��Name$ txtFunction��$��0��$��0�� �� AcceptsReturn .  �� 
AcceptsTab . $��10,25,10,10q�	 �� MinLines$	 23��$��Stretch=�$��Stretch=�"
 �� VerticalScrollBarVisibility$
 Visible=�$ �� HorizontalScrollBarVisibility$
 Auto=�$	��350������ *!SelectedItem.Value.LastFunction+$ lbFunctions���� $	��298��$	��150��
���   �$��1q�$	��Top=�$y�	Collapsed=�$��
0,-170,0,0q�$��Right=�
�������._��� $
��Auto=�.���� -    ��Name$ stkAutoComplete���� $��1��$��0��$��Center=�$��Stretch=�
������� �� ShowsPreview . $��5���� $��
10,0,10,10q�$��2��$��0��.+��� $��	Functions���� -   $	��Add��$
��10,1q�$��
10,0,10,10q��� -   $��Remove��$
��10,1q�$��
10,0,10,10q��� -   $
��Save��$
��10,1q�$��
10,0,10,10q��� -   $��Close��$
��10,1q�$��
10,0,10,10q��� -	    ��Name$ lbFunctions��$��2��$��0��$��10,150,10,10q�$	��230������ .R��� ���� *Value.Title+