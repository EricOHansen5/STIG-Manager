   M S B A M L   `   `   `  ���� I  ESTIG_Manager_2, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null9!clr-namespace:STIG_Manager_2.ViewSTIG_Manager_2.View  )    #STIG_Manager_2.View.RunRemoteWindow   W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     @d2http://schemas.microsoft.com/expression/blend/2008     Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     3local!clr-namespace:STIG_Manager_2.View     -   $��Run_Remote_Window��  � Title$  
Run Remote��$	��450��$	��800��.��� -    �Name$ MainGrid�� � ColumnDefinitions �� $��3* ��� $
��Auto ��� $��* � � RowDefinitions �� $��* �.+��� $��0��$��0��$��
Computers:��$
��Left=�$	��Top=��� $��Status:��$��Center=�$	��Top=�$��65,0,0,0q��� -   $��lblCountDown�� �� ContentStringFormat$ {0} Seconds��$��Center=�$	��Top=�$��	175,0,0,0q����� *	CountDown+�� -   $��lblCheckOnline��$��0��$��0��$��Checking Online Statuses��$��Right=�$	��Top=�$��	0,0,100,0q�y��� *
IsChecking+� -   $��pbCheckOnline��$��3��$��Right=�$	��Top=�$��
0,22,106,0q�$	��132�� � IsIndeterminate . y��� *
Visibility+ �� ElementName$ lblCheckOnline���� -    ��Name$ btnCheckNow��$
��10,1q�$��	Check Now��$��	10,5,10,0q�$��Right=�$	��Top=�&   System.Windows.Controls.DataGrid  -     Name$ dgComputers��$��0��$��0��$��10,27,10,10q�	   AutoGenerateColumns	 .  
   CanUserDeleteRows
 .    CanUserAddRows .    CanUserResizeRows .     CanUserResizeColumns .    AlternatingRowBackground
 ����� �� AlternationCount$ 2��   SelectionMode$ Single=����� *	Computers+ �� Mode$ TwoWay=� �� UpdateSourceTrigger$ PropertyChanged=� �� NotifyOnTargetUpdated .    Columns 4  .System.Windows.Controls.DataGridCheckBoxColumn  ,  &System.Windows.Controls.DataGridColumn   Width5  /System.Windows.Controls.DataGridLengthConverter$
 1.2*    CanUserSort .  1  +System.Windows.Controls.DataGridBoundColumn   Binding �� *
IsSelected+ �� NotifyOnSourceUpdated .  .  �� NotifyOnValidationError . " �� ValidatesOnNotifyDataErrors .    HeaderTemplate �� .R��� -   $��	4,-1,10,0q�$��0q�$��Stretch=�$��Center=�$��Center=�.��
Select All0  *System.Windows.Controls.DataGridTextColumn     Header$
 Name��$ 3*  �� *Name+$ TwoWay=� .  .    ElementStyle ��  �� 
TargetType" ��.���  �� Property � ��  �� Value$  Center=���  � ��$
  10,1q�  $ Online��$ 1*  �� *Online+ �� " ��.���  � ��$  Center=���  � ��$
  10,1q�! �� Triggers! �� " �� Binding" �� *Online+# �� Value# True.a���  � ��
  � � ���  � ��$  Online���� " �� *Online+	# False.a���  � ��
  �  ����  � ��$  Offline��4  .System.Windows.Controls.DataGridTemplateColumn  $ Running��$ 2* $   CellTemplate$ �� .R�]� .+��� $
��10,3q����� *
FinishText+� $
��10,3q� .  $��5��% � Value% �� *	Completed+&   	CellStyle& �� *  $System.Windows.Controls.DataGridCell"  .���  � ��$  26���� $��1��$��0��$��Center=�$��Stretch=�
�������' �� ShowsPreview' . $��5���� $��2��$��0��.+��� $��Operations:���� -	   $ btnRun_Selected��$��Run Selected��$��
10,10,10,0q�� -
   ( �Name$( progressBar_Run�� . $��	10,0,10,5q�$��5��$y�Hidden=��� -   $ btnCancel_Run��$��
Cancel Run��$��10,10,10,10q�{�.  �� -   $ btnSave_Computers��$
��10,1q�$��10q�$
��Save������ " ��! �� " �� *Saved+# True.a���  � ��
  ������ " �� *Saved+	# False.a���  � ��  �	#FFDDDDDD�� -   $ btnClose��$
��10,1q�$��10q�$��Close���� -   $ 	btnDelete��$
��10,1q�$��10q�$��Delete��
���  ��