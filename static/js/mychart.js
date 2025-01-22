// function pieChart(name, mydom, datas) {

//     Highcharts.setOptions({
//         colors: ['#ff0066', 'orange', '#68b840', '#759dfa']
//     });
//     Highcharts.chart(name, {
//         chart: {
//             type: 'pie',

//             options3d: {
//                 enabled: true,
//                 alpha: 45,
//                 beta: 0
//             }
//         },
//         // title: {
//         //     text: null

//         // },
//         title: {
//             text: mydom
//         },

//         credits: {
//             enabled: false
//         },
//         accessibility: {
//             point: {
//                 valueSuffix: '%'
//             }
//         },
//         tooltip: {
//             pointFormat: '{series.name}: <b>{point.percentage:.1f}%</b>',
           
//         },
//         plotOptions: {
//             pie: {
//                 allowPointSelect: true,
//                 cursor: 'pointer',
//                 depth: 35,
//                 dataLabels: {
//                     enabled: true,
//                     format: '{point.name}'
//                 }

//             }
//         },
//         series: [{
//             type: 'pie',
//             name: mydom,
//             data: datas,
//             colorByPoint: true,

//         }]
//     });
// }


// // New Pie Chat For Deshboard

function pieChart(name, mydom, datas) {

    Highcharts.chart(name, {
        chart: {
          type: 'pie'
        },
        title: {
          text: mydom,
        },
        tooltip: {
          valueSuffix: '%'
        },
        plotOptions: {
          series: {
            allowPointSelect: true,
            cursor: 'pointer',
            dataLabels: [{
              enabled: true,
              distance: 20
            }, {
              enabled: true,
              distance: -40,
              format: '{point.percentage:.1f}%',
              style: {
                fontSize: '1.2em',
                textOutline: 'none',
                opacity: 0.7
              },
              filter: {
                operator: '>',
                property: 'percentage',
                value: 10
              }
            }]
          }
        },
        series: [
          {
            name: name,
            colorByPoint: true,
            data: datas
          }
        ]
      });
}



