   M S B A M L   `   `   `  ����I  ESTIG_Manager_2, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null9!clr-namespace:STIG_Manager_2.ViewSTIG_Manager_2.View  5   	   )    #STIG_Manager_2.View.RunRemoteWindow   5   	   W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   3local!clr-namespace:STIG_Manager_2.View     5   	   -   5        $��Run_Remote_Window��5   5     � Title$  
Run Remote��6	   $	��450��6   $	��800��6)   .��5	      � -   5         �Name$ MainGrid��5	       � ColumnDefinitions 5
   
   �� 5      $��3* �6   �� 5      $
��Auto �6   �� 5      $��* �6    � RowDefinitions 5   
   �� 5      $��* �6   .+�5   
   �� $��0��6   $��0��6    $��
Computers:��6-   $
��Left=�6B   $	��Top=�6]   �� 5   
   $��Status:��6   $��Center=�6"   $	��Top=�6?   $��65,0,0,0q�6W   �� 5   
   -   5        $��lblCountDown��5       �� ContentStringFormat$ {0} Seconds��6B   $��Center=�6f   $	��Top=�6�   $��	175,0,0,0q�6�   ��6$   �� *	CountDown+6�   �� 5   
   -   5        $��lblCheckOnline��5      $��0��6&   $��0��66   $��Checking Online Statuses��6C   $��Right=�6f   $	��Top=�6�   $��	0,0,100,0q�6�   y�6�   �� *
IsChecking+� 5   
   -   5        $��pbCheckOnline��5      $��3��6+   $��Right=�66   $	��Top=�6R   $��
0,22,106,0q�6j   $	��132��6�    � IsIndeterminate . y�6~   �� *
Visibility+ �� ElementName$ lblCheckOnline��6�   �� 5   
   -   5         ��Name$ btnCheckNow��5      $
��10,1q�6&   $��	Check Now��65   $��	10,5,10,0q�6I   $��Right=�6\   $	��Top=�6x   6�   &   System.Windows.Controls.DataGrid  5   
   -   5          Name$ dgComputers��5      $��0��6(   $��0��65   $��10,27,10,10q�6E   	   AutoGenerateColumns	 .  
   CanUserDeleteRows
 .    CanUserAddRows .    CanUserResizeRows .     CanUserResizeColumns .    AlternatingRowBackground
 ����� �� AlternationCount$ 2��5   T      SelectionMode$ Single=�5      ��5      �� *	Computers+ �� Mode$ TwoWay=� �� UpdateSourceTrigger$ PropertyChanged=� �� NotifyOnTargetUpdated .    Columns 5      4  .System.Windows.Controls.DataGridCheckBoxColumn  5      ,  &System.Windows.Controls.DataGridColumn   Width5  /System.Windows.Controls.DataGridLengthConverter$
 1.2* 6)      CanUserSort .  1  +System.Windows.Controls.DataGridBoundColumn   Binding 66   �� *
IsSelected+ �� NotifyOnSourceUpdated .  .  �� NotifyOnValidationError . " �� ValidatesOnNotifyDataErrors .    HeaderTemplate 5      �� 5       .R�5!      �� -   5        $��	4,-1,10,0q�5!   A   $��0q�6U   $��Stretch=�6`   $��Center=�6|   $��Center=�6�   .��6�   
Select All6�   5"      5$      0  *System.Windows.Controls.DataGridTextColumn  5&         Header$
 Name��6%   $ 3* 63    6>   �� *Name+$ TwoWay=� .  .    ElementStyle 5'      �� 5(       �� 
TargetType" ��6    .�5)      ��  �� Property � ��  �� Value$  Center=�6B   �� 5*       � ��$
  10,1q�67   5+      5-        5/      $ Online��6%   $ 1* 65    6@   �� *Online+ 50      �� 51      " ��6    .�52      ��  � ��$  Center=�6B   �� 53       � ��$
  10,1q�67   ! �� Triggers! 54      �� 55   "   " �� Binding" 6.   �� *Online+# �� Value# True6I   .a�56   &   ��  � ��
  � � �6C   �� 57   &    � ��$  Online��6=   58   #   �� 59   "   " 6.   �� *Online+	# False6I   .a�5:   &   ��  � ��
  �  ��6C   �� 5;   &    � ��$  Offline��6=   5<   #   5>      5@      4  .System.Windows.Controls.DataGridTemplateColumn  5A      $ Running��6)   $ 2* 6:   $   CellTemplate$ 5B      �� 5C      .R�5D      ]� .+�5E   "   �� $
��10,3q�6,   ��6:   �� *
FinishText+� 5F   "   $
��10,3q�6.    .  $��5��6p   % � Value% 6T   �� *	Completed+6p   5G      5H      5J      &   	CellStyle& 5L      �� 5M      *  $System.Windows.Controls.DataGridCell"  6   .�5N      ��  � ��$  26��6/   5O      5Q      �� 5R   
   $��1��6   $��0��6'   $��Center=�64   $��Stretch=�6Q   
�������' �� ShowsPreview' . $��5��6�   �� 5S   
   $��2��6   $��0��6%   .+�5T      �� $��Operations:��6   �� 5U      -	   5        $ btnRun_Selected��5U      $��Run Selected��6.   $��
10,10,10,0q�6E   6Y   � 5V      -
   5        ( �Name$( progressBar_Run��5V       . $��	10,0,10,5q�6J   $��5��6]   $y�Hidden=�6h   �� 5W      -   5        $ btnCancel_Run��5W      $��
Cancel Run��6,   $��10,10,10,10q�6A   {�.  6h   �� 5Y      -   5        $ btnSave_Computers��5Y      $
��10,1q�60   $��10q�6?   $
��Save��6K   ��5Z      �� 5[      " ��6   ! 5\      �� 5]      " 6*   �� *Saved+# True6D   .a�5^   "   ��  � ��
  ����6?   5_      �� 5`      " 6*   �� *Saved+	# False6D   .a�5a   "   ��  � ��  �	#FFDDDDDD6?   5b      5d      5f      �� 5g      -   5        $ btnClose��5g      $
��10,1q�6'   $��10q�66   $��Close��6B   6R   �� 5h      -   5        $ 	btnDelete��5h      $
��10,1q�6(   $��10q�67   $��Delete��6C   
���  ��6i   5i      5j      5k      