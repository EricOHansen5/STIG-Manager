   M S B A M L   `   `   `  ����I  ESTIG_Manager_2, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null9!clr-namespace:STIG_Manager_2.ViewSTIG_Manager_2.View  5   	   !    STIG_Manager_2.View.Message   5   	   W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   3local!clr-namespace:STIG_Manager_2.View     5   	     � Title$  Results��5   	   $	��300��6   $	��400��6&    � WindowStartupLocation$ CenterScreen=�62    � Topmost . .��5	      �  � ColumnDefinitions 5
   
   �� 5      $��1* �6   �� 5      $��6* �6    � RowDefinitions 5   
   �� 5      $��4* �6   �� 5      $��* �6   .+�5   
   �� -   5        $��stkIcons��5   !   $��10q�6   6!   �� 5   
   $��10q�6   $
��Auto=�6#   $��0��6F   $��1��6S   .��5      �� $��WrapWithOverflow=�6-   ��6   �� *Msg+6-   5      A� 5   
   $��1��6   $��0q�6#    A� Columns$ 4��6.   $��2��6:   ���	#FFE8E8E8.+�5      �� -   5         ��Name$ btnOk��5      $��OK��6$   $
��20,1q�61   $��10q�6@   $��Center=�6L   $��Center=�6i   6�   �� 5      -   5        $ btnYes��5      $	��Yes��6%   $
��20,1q�63   $��10q�6B   $��Center=�6N   $��Center=�6k   6�   �� 5      -   5        $ btnNo��5      $��No��6$   $
��20,1q�61   $��10q�6@   $��Center=�6L   $��Center=�6i   6�   �� 5      -   5        $ 	btnCancel��5      $��Cancel��6(   $
��20,1q�69   $��10q�6H   $��Center=�6T   $��Center=�6q   6�   5      5      5      